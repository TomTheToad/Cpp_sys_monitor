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
  static std::string PrintCpuStats(std::vector<std::string> values1,
                                   std::vector<std::string> values2);
  static bool isPidExisting(string pid);
};

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
  string str = line;
  istringstream buf(str);
  istream_iterator<string> beg(buf), end;
  vector<string> values(beg, end);

  // extract stats
  float utime = stof(ProcessParser::getProcUpTime(pid));
  float stime = stof(values[14]);
  float cutime = stof(values[15]);
  float cstime = stof(values[16]);
  float starttime = stof(values[21]);
  // TODO: getSysUpTime() to be defined
  float uptime = ProcessParser::getSysUpTime();
  float freq = sysconf(_SC_CLK_TCK);
  float total_time = utime + stime + cutime + cstime;
  float seconds = uptime - (starttime / freq);
  result = 100.0 * ((total_time / freq) / seconds);

  // return
  return to_string(result);
}

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

string ProcessParser::getProcUser(string pid) {
  // Fields
  string line;
  string name = "Uid:";
  string result = "";
  string path = Path::basePath() + pid + Path::statusPath();
  ifstream stream;

  // Open stream for UID query
  Util::getStream(path, stream);

  // Get UID
  while (std::getline(stream, line)) {
    if (line.compare(0, name.size(), name) == 0) {
      istringstream buf(line);
      istream_iterator<string> beg(buf), end;
      vector<string> values(beg, end);
      result = values[1];
      break;
    }
  }

  // Open stream for name of user with above UID
  Util::getStream("/etc/passwd", stream);
  name = ("x:" + result);

  // Search for user name associated with UID
  while (std::getline(stream, line)) {
    if (line.find(name) != std::string::npos) {
      result = line.substr(0, line.find(":"));
      return result;
    }
  }
  return "";
}

vector<string> ProcessParser::getPidList() {
  // Fields
  DIR *dir;
  vector<string> container;

  // Open pro dir
  if (!(dir = opendir("\proc")))
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