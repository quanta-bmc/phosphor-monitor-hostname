#include <certificate_handler.hpp>
#include <boost/container/flat_map.hpp>
#include <sdbusplus/asio/object_server.hpp>
#include <iostream>
#include <stdio.h>

using namespace std::string_literals;
namespace monitor_hostname
{
    void install_certificate(std::shared_ptr<sdbusplus::asio::connection> conn, const std::string& certPath)
    {
        if(access(certPath.c_str(), F_OK) == 0)
        {
            conn->async_method_call(
                [certPath](boost::system::error_code ec) {
                    if (ec)
                    {
                        std::cerr << "Replace Certificate Fail.." << std::endl;
                        return;
                    }

                    std::cerr << "Replace Certificate Success, remove temporary certificate file.." << std::endl;
                    remove(certPath.c_str());
                },
                "xyz.openbmc_project.Certs.Manager.Server.Https",
                "/xyz/openbmc_project/certs/server/https/1",
                "xyz.openbmc_project.Certs.Replace", "Replace",
                certPath);
        }
        else
        {
            std::cerr << "install_certificate Fail..file not exist" << std::endl;
        }
    }

    std::string parseSubject(const std::string& subject)
    {
        std::size_t cnPos = subject.find("CN=");
        if (cnPos != std::string::npos)
        {
            std::string cn = subject.substr(cnPos);
            cnPos = cn.find(",");
            if (cnPos != std::string::npos)
            {
                cn = cn.substr(0, cnPos);
            }

            cnPos = cn.find("=");
            std::string cnValue = cn.substr(cnPos+1);

            return cnValue;
        }
        std::cerr << "Can't find CN in subject" << std::endl;
        return "";
    }

    void monitor_hostname_signal(std::shared_ptr<sdbusplus::asio::connection> conn)
    {
        static std::unique_ptr<sdbusplus::bus::match::match> hostnameSignalMonitor;

        auto param = "type='signal',interface='org.freedesktop.DBus.Properties',"s +
                     "member='PropertiesChanged',"s +
                     "path='/xyz/openbmc_project/network/config',"s +
                     "arg0='xyz.openbmc_project.Network.SystemConfiguration'"s;

        hostnameSignalMonitor = std::make_unique<sdbusplus::bus::match::match>(
            *conn, param,
            [conn](sdbusplus::message::message& message) {
                // Callback when dbus signal occurs
                try
                {
                    std::string iface;
                    boost::container::flat_map<std::string, std::variant<std::string>>
                        changed_properties;
                    std::string hostname;

                    message.read(iface, changed_properties);

                    auto it = changed_properties.find("HostName");
                    if (it != changed_properties.end())
                    {
                        hostname = std::get<std::string>(it->second);
                        std::cerr << "Read hostname from signal: "<< hostname << std::endl;

                        conn->async_method_call(
                        [hostname, conn](boost::system::error_code ec,
                        const std::variant<std::string>& currentCertSubject) {
                            if (ec)
                            {
                                return;
                            }
                            const std::string* subject = std::get_if<std::string>(&currentCertSubject);
                            if (subject == nullptr)
                            {
                                std::cerr << "Unable to read subject" << std::endl;
                                return;
                            }

                            std::string cnValue = parseSubject(*subject);
                            if(!cnValue.empty())
                            {
                                std::cerr << "Current HTTPs Certificate Subject: "<< cnValue << ", New HostName: " << hostname << std::endl;
                                if(cnValue != hostname)
                                {
                                    certificate::CertHandler certHandler;
                                    certHandler.generateSslCertificate(hostname);
                                    install_certificate(conn, certificate::tmpCertPath);
                                }
                            }
                        },
                        "xyz.openbmc_project.Certs.Manager.Server.Https",
                        "/xyz/openbmc_project/certs/server/https/1",
                        "org.freedesktop.DBus.Properties", "Get",
                        "xyz.openbmc_project.Certs.Certificate", "Subject");
                    }
                }
                catch (std::exception& e)
                {
                    std::cerr << "Unable to read hostname" << std::endl;
                    return;
                }
            });
    }
} // namespace monitor_hostname

int main(int argc, char* argv[])
{
    boost::asio::io_service io;
    std::shared_ptr<sdbusplus::asio::connection> conn;

    std::cerr << "Start Monitor hostname service..." << std::endl;

    conn = std::make_shared<sdbusplus::asio::connection>(io);
    monitor_hostname::monitor_hostname_signal(conn);

    io.run();
    return 0;
}
