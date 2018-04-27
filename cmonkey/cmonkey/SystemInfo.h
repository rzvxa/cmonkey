#ifndef SYSTEM_INFO_
#define SYSTEM_INFO_

#include <string>
#include <vector>

class SystemInfo
{
public:
	static SystemInfo Instance();
	std::string Architecture() { return architecture_; }
	std::string WinVersion() { return win_ver_; }
	std::string CPU() { return cpu_; }
	std::string User() { return user_; }
	std::string PCName() { return pc_name_; }
	std::string IsAdmin() { return is_admin_; }
	std::vector<std::string> GPU() { return gpu_; }
	std::string Motherboard() { return motherboard_; }
	std::string ChassisType() { return chassis_type_; }
	std::string TotalRam() { return total_ram_; }
	std::string Bios() { return bios_; }
	std::string PID() { return pid_; }
	std::string Mac() { return mac_; }
	std::string IPv4() { return ipv4_; }
	std::vector<std::string> Antivirus() { return antivirus_; }
	std::vector<std::string> Firewall() { return firewall_; }
	std::vector<std::string> Antispyware() { return antispyware_; }
	std::string GeoLocation() { return geolocation_; }
	std::string UniqueID() { return unique_id_; }
	~SystemInfo();
private:
	SystemInfo();
	std::string architecture_;
	std::string win_ver_;
	std::string cpu_;
	std::string user_;
	std::string pc_name_;
	std::string is_admin_;
	std::vector<std::string> gpu_;
	std::string motherboard_;
	std::string chassis_type_;
	std::string total_ram_;
	std::string bios_;
	std::string pid_;
	std::string mac_;
	std::string ipv4_;
	std::vector<std::string> antivirus_;
	std::vector<std::string> firewall_;
	std::vector<std::string> antispyware_;
	std::string geolocation_;
	std::string unique_id_;
	
	std::string machine();
	std::string platform();
	std::string processor();
	std::string user();
	std::string pcname();
	std::string isAnAdmin();
	std::vector<std::string> gpu();
	std::string motherboard();
	std::string chassistype();
	std::string totalram();
	std::string bios();
	std::string pid();
	std::string mac();
	std::string ipv4(const std::string&);
	std::vector<std::string> antivirus();
	std::vector<std::string> firewall();
	std::vector<std::string> antispyware();
	std::string geolocation();
	std::string unique_id();
};

#endif // !SYSTEM_INFO_