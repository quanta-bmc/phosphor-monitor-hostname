#include <boost/container/flat_map.hpp>
#include <iostream>
#include <sdbusplus/asio/object_server.hpp>
#include <stdio.h>
#include <certificate_handler.hpp>

using namespace std::string_literals;
namespace monitor_hostname
{
	static boost::asio::io_service io;
	std::shared_ptr<sdbusplus::asio::connection> conn;
	static std::unique_ptr<sdbusplus::bus::match::match> hostnameSignalMonitor_ ;
	
	static void install_certificate(std::string certPath)
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
	
	static void monitor_hostname_signal()
	{
		const auto param = "type='signal',interface='org.freedesktop.DBus.Properties',"s + 
						"member='PropertiesChanged',"s +
						"path='/xyz/openbmc_project/network/config',"s +
						"arg0='xyz.openbmc_project.Network.SystemConfiguration'"s;
	
		hostnameSignalMonitor_ = std::make_unique<sdbusplus::bus::match::match>(
			*conn, param,
			[](sdbusplus::message::message& message) {
				// Callback when dbus signal occurs
				std::string iface;
				boost::container::flat_map<std::string, std::variant<std::string>>
					changed_properties;
				std::string hostname;	
				try
				{
					message.read(iface, changed_properties);
					
					auto it = changed_properties.find("HostName");
					if (it != changed_properties.end())
					{	
						hostname = std::get<std::string>(it->second);
						std::cerr << "Read hostname from signal: "<< hostname << std::endl;
						
						conn->async_method_call(
						[hostname](boost::system::error_code ec,
						const std::variant<std::string>& currentCertSubject) {
							if (ec)
							{
								return;
							}
							const std::string* sbuject = std::get_if<std::string>(&currentCertSubject);
							if (sbuject == nullptr)
							{
								std::cerr << "Unable to read Sbuject" << std::endl;
								return;
							}
							
							std::size_t cnPos = (*sbuject).find("CN=");
							if (cnPos != std::string::npos)
							{
								std::string cn = (*sbuject).substr (cnPos);
								
								cnPos = cn.find(",");
								if (cnPos != std::string::npos)
								{
									cn = cn.substr (0,cnPos);
								}
								
								cnPos = cn.find("=");
								std::string cnValue = cn.substr (cnPos+1);
								
								std::cerr << "Current HTTPs Certificate Subject: "<< cnValue << ", New HostName: " << hostname << std::endl;
								if(cnValue.compare(hostname)!=0)
								{
									certificate::generateSslCertificate(hostname);
									install_certificate(certificate::tmpCertPath);
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
    std::cerr << "Start Monitor hostname service..." << std::endl;
    
	monitor_hostname::conn = std::make_shared<sdbusplus::asio::connection>(monitor_hostname::io);
    monitor_hostname::monitor_hostname_signal();

    monitor_hostname::io.run();
    return 0;
}
