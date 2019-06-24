#include "constants.h"
#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <dirent.h>
#include <fstream>
#include <iostream>
#include <iterator>
#include <math.h>
#include <sstream>
#include <stdexcept>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <thread>
#include <time.h>
#include <unistd.h>
#include <vector>

using namespace std;
using std::string;

class ProcessParser {
private:
  std::ifstream stream;

public:
  static string getCmd(string pid);
  static vector<string> getPidList();
  static std::string getVmSize(string pid);
  static std::string getCpuPercent(string pid);
  static long int getSysUpTime();
  static std::string getProcUpTime(string pid);
  static string getProcUser(string pid);
  static vector<string> getSysCpuPercent(string coreNumber = "");
  static float getSysRamPercent();
  static string getSysKernelVersion();
  static int getNumberOfCores();
  static int getTotalThreads();
  static int getTotalNumberOfProcesses();
  static int getNumberOfRunningProcesses();
  static string getOSName();
  static std::string printCpuStats(std::vector<std::string> values1,
                                   std::vector<std::string> values2);
  // The below function was never defined, yet part of the starter code.
  // I believe it was removed
  // static bool isPidExisting(string pid);
};

// Helper functions
// TODO: the given code has used multiple naming conventions.
// Figure out what these two functions should be named.
float get_sys_active_cpu_time(vector<string> values) {
  return (stof(values[S_USER]) + stof(values[S_NICE]) + stof(values[S_SYSTEM]) +
          stof(values[S_IRQ]) + stof(values[S_SOFTIRQ]) +
          stof(values[S_STEAL]) + stof(values[S_GUEST]) +
          stof(values[S_GUEST_NICE]));
}

float get_sys_idle_cpu_time(vector<string> values) {
  return (stof(values[S_IDLE]) + stof(values[S_IOWAIT]));
}

// MARK: Begin assigned methods

// Get virtual memory size
string ProcessParser::getVmSize(string pid) {
  // Fields
  string line;
  string value;
  float result;
  string name = "VmData";
  ifstream stream;

  // Define file path
  string path = (Path::basePath() + pid + Path::statusPath());

  // Open stream
  Util::getStream(path, stream);

  while (std::getline(stream, line)) {
    // Search ea line
    if (line.compare(0, name.size(), name) == 0) {
      // slice
      istringstream buf(line);
      istream_iterator<string> beg(buf), end;
      vector<string> values(beg, end);

      // convert kB -> GB
      result = (stof(values[1]) / float(1024 * 1024));
      break;
    }
  }
  return to_string(result);
}

// Get cpu percentage
string ProcessParser::getCpuPercent(string pid) {

  // Fields
  string line;
  string value;
  float result;
  ifstream stream;

  // Define file path
  string path = (Path::basePath() + pid + "/" + Path::statPath());

  // Open stream
  Util::getStream(path, stream);
  std::getline(stream, line);
  // string str = line;
  istringstream buf(line);
  istream_iterator<string> beg(buf), end;
  vector<string> values(beg, end);

  // extract stats
  float utime = stof(ProcessParser::getProcUpTime(pid));
  float stime = stof(values[14]);
  float cutime = stof(values[15]);
  float cstime = stof(values[16]);
  float starttime = stof(values[21]);
  float uptime = ProcessParser::getSysUpTime();
  float freq = sysconf(_SC_CLK_TCK);
  float total_time = utime + stime + cutime + cstime;
  float seconds = uptime - (starttime / freq);
  result = 100.0 * ((total_time / freq) / seconds);

  // return
  return to_string(result);
}

// Get process up time
string ProcessParser::getProcUpTime(string pid) {
  // Fields
  ifstream stream;
  string line;
  string value;
  float result;

  // Define file path
  string path = (Path::basePath() + pid + "/" + Path::statPath());

  // Open stream
  Util::getStream(path, stream);
  std::getline(stream, line);

  string str = line;
  istringstream buf(str);
  istream_iterator<string> beg(buf), end;
  vector<string> values(beg, end);

  return to_string(float(stof(values[13]) / sysconf(_SC_CLK_TCK)));
}

// Get system up time
long int ProcessParser::getSysUpTime() {
  // Fields
  string line;
  ifstream stream;
  string path = Path::basePath() + Path::upTimePath();

  Util::getStream(path, stream);
  std::getline(stream, line);
  istringstream buf(line);
  istream_iterator<string> beg(buf), end;
  vector<string> values(beg, end);
  return stoi(values[0]);
}

// Get user processes
// This method was modified to use two individual streams
string ProcessParser::getProcUser(string pid) {
  // Fields
  string line;
  string name = "Uid:";
  string result = "";
  string path = Path::basePath() + pid + Path::statusPath();
  ifstream uid_stream;
  ifstream user_stream;

  // Open stream for UID query
  Util::getStream(path, uid_stream);

  // Get UID
  while (std::getline(uid_stream, line)) {
    if (line.compare(0, name.size(), name) == 0) {
      istringstream buf(line);
      istream_iterator<string> beg(buf), end;
      vector<string> values(beg, end);
      result = values[1];
      break;
    }
  }

  // Open stream for name of user with above UID
  Util::getStream("/etc/passwd", user_stream);
  name = ("x:" + result);

  // Search for user name associated with UID
  while (std::getline(user_stream, line)) {
    if (line.find(name) != std::string::npos) {
      result = line.substr(0, line.find(":"));
      return result;
    }
  }
  return "";
}

// Get PID list
vector<string> ProcessParser::getPidList() {
  // Fields
  DIR *dir;
  vector<string> container;

  // Open pro dir
  if (!(dir = opendir("/proc")))
    throw std::runtime_error(std::strerror(errno));

  // Iterate over all directories within proc
  while (dirent *dirp = readdir(dir)) {

    // make sure item being pointed to is a directory
    if (dirp->d_type != DT_DIR) {
      // If not, skip
      continue;
    }

    // check directory name is all digits
    if (all_of(dirp->d_name, dirp->d_name + std::strlen(dirp->d_name),
               [](char c) { return std::isdigit(c); })) {
      // passed checks, add to container vector
      container.push_back(dirp->d_name);
    }
  }

  // Make sure directory closed
  if (closedir(dir)) {
    throw std::runtime_error(std::strerror(errno));
  }

  // Finally return container with dir of numbered processes
  return container;
}

// Get command for given process
string ProcessParser::getCmd(string pid) {
  // Fields
  string line;
  ifstream stream;
  string path = Path::basePath() + pid + Path::cmdPath();

  // Open stream
  Util::getStream(path, stream);
  std::getline(stream, line);
  return line;
}

// Get number of cores
int ProcessParser::getNumberOfCores() {
  // Fields
  string line;
  string name = "cpu cores";
  string path = Path::basePath() + "cpuinfo";
  ifstream stream;

  Util::getStream(path, stream);
  while (std::getline(stream, line)) {
    if (line.compare(0, name.size(), name) == 0) {
      istringstream buf(line);
      istream_iterator<string> beg(buf), end;
      vector<string> values(beg, end);
      return stoi(values[3]);
    }
  }
  return 0;
}

// Get cpu % in use by the system
vector<string> ProcessParser::getSysCpuPercent(string coreNumber) {
  // Fields
  string line;
  string name = "cpu" + coreNumber;
  ifstream stream;
  string path = Path::basePath() + Path::statPath();

  Util::getStream(path, stream);

  while (std::getline(stream, line)) {
    if (line.compare(0, name.size(), name) == 0) {
      istringstream buf(line);
      istream_iterator<string> beg(buf), end;
      vector<string> values(beg, end);
      return values;
    }
  }
  return (vector<string>());
}

// TODO: check internal method calls are named correctly. Class material shows
// camel and serpent case.
// Print cpu statistics
string ProcessParser::printCpuStats(vector<string> values1,
                                    vector<string> values2) {
  float activeTime =
      get_sys_active_cpu_time(values2) - get_sys_active_cpu_time(values1);
  float idleTime =
      get_sys_idle_cpu_time(values2) - get_sys_idle_cpu_time(values1);
  float totalTime = activeTime + idleTime;
  float result = 100.0 * (activeTime / totalTime);
  return to_string(result);
}

// Get percent of system ram in use
float ProcessParser::getSysRamPercent() {
  // Fields
  // names
  string name1 = "MemAvailable:";
  string name2 = "MemFree:";
  string name3 = "Buffers:";

  // result type variables
  string line;
  string value;
  int result;
  float total_mem = 0;
  float free_mem = 0;
  float buffers = 0;

  // file reading variables
  ifstream stream;
  string path = Path::basePath() + Path::memInfoPath();

  Util::getStream(path, stream);
  while (std::getline(stream, line)) {

    if (total_mem != 0 && free_mem != 0) {
      break;
    }

    if (line.compare(0, name1.size(), name1) == 0) {
      istringstream buf(line);
      istream_iterator<string> beg(buf), end;
      vector<string> values(beg, end);
      total_mem = stof(values[1]);
    }

    if (line.compare(0, name2.size(), name2) == 0) {
      istringstream buf(line);
      istream_iterator<string> beg(buf), end;
      vector<string> values(beg, end);
      free_mem = stof(values[1]);
    }

    if (line.compare(0, name3.size(), name3) == 0) {
      istringstream buf(line);
      istream_iterator<string> beg(buf), end;
      vector<string> values(beg, end);
      buffers = stof(values[1]);
    }
  }

  return float(100.0 * (1 - (free_mem / (total_mem - buffers))));
}

// Get Kernal info (version)
string ProcessParser::getSysKernelVersion() {
  // Fields
  string line;
  string name = "Linux version ";
  ifstream stream;
  string path = Path::basePath() + Path::versionPath();

  Util::getStream(path, stream);

  while (std::getline(stream, line)) {
    if (line.compare(0, name.size(), name) == 0) {
      istringstream buf(line);
      istream_iterator<string> beg(buf), end;
      vector<string> values(beg, end);
      return values[2];
    }
  }
  return "";
}

// TODO: verify correct method name. Class material differs
// Get operating system name
string ProcessParser::getOSName() {
  // Fields
  string line;
  string result;
  string name = "PRETTY_NAME=";
  ifstream stream;
  string path = "/etc/os-release";

  Util::getStream(path, stream);

  while (std::getline(stream, line)) {
    if (line.compare(0, name.size(), name) == 0) {
      std::size_t found = line.find("=");
      found++;
      result = line.substr(found);
      result.erase(std::remove(result.begin(), result.end(), '"'),
                   result.end());
      return result;
    }
  }
  return "";
}

// Get total number of logic threads
int ProcessParser::getTotalThreads() {
  // Fields
  string line;
  int result = 0;
  string name = "Threads:";
  vector<string> _list = ProcessParser::getPidList();
  ifstream stream;
  string path;

  // TODO: test this loop vs above
  // This method differs from class material slightly.
  for (string pid : _list) {
    path = Path::basePath() + pid + Path::statusPath();
    Util::getStream(path, stream);

    while (std::getline(stream, line)) {
      if (line.compare(0, name.size(), name) == 0) {
        istringstream buf(line);
        istream_iterator<string> beg(buf), end;
        vector<string> values(beg, end);
        result += stoi(values[1]);
        break;
      }
    }
    return result;
  }
}

// Get total number of processes (running and idle)
int ProcessParser::getTotalNumberOfProcesses() {
  // Fields
  string line;
  int result = 0;
  string name = "processes";
  ifstream stream;
  string path = Path::basePath() + Path::statPath();

  Util::getStream(path, stream);

  while (std::getline(stream, line)) {
    if (line.compare(0, name.size(), name) == 0) {
      istringstream buf(line);
      istream_iterator<string> beg(buf), end;
      vector<string> values(beg, end);
      result += stoi(values[1]);
      break;
    }
  }
  return result;
}

// Get total number of running processes
int ProcessParser::getNumberOfRunningProcesses() {
  // Fields
  string line;
  int result = 0;
  string name = "procs_running";
  ifstream stream;
  string path = Path::basePath() + Path::statPath();

  Util::getStream(path, stream);

  while (std::getline(stream, line)) {
    if (line.compare(0, name.size(), name) == 0) {
      istringstream buf(line);
      istream_iterator<string> beg(buf), end;
      vector<string> values(beg, end);
      result += stoi(values[1]);
      break;
    }
  }
  return result;
}