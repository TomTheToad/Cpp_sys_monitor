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
  string path = (Path::basePath() + pid + Path::statPath());

  // Open stream
  // TODO: util takes a stream but returns a stream?
  Util::getStream(path, stream);
  getline(stream, line);
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

/*
string ProcessParser::getCpuPercent(string pid)
{
    string line;
    string value;
    float result;
    ifstream stream = Util::getStream((Path::basePath()+ pid + "/" +
Path::statPath())); getline(stream, line); string str = line; istringstream
buf(str); istream_iterator<string> beg(buf), end; vector<string> values(beg,
end); // done!
    // acquiring relevant times for calculation of active occupation of CPU for
selected process float utime = stof(ProcessParser::getProcUpTime(pid)); float
stime = stof(values[14]); float cutime = stof(values[15]); float cstime =
stof(values[16]); float starttime = stof(values[21]); float uptime =
ProcessParser::getSysUpTime(); float freq = sysconf(_SC_CLK_TCK); float
total_time = utime + stime + cutime + cstime; float seconds = uptime -
(starttime/freq); result = 100.0*((total_time/freq)/seconds); return
to_string(result);
}
 */