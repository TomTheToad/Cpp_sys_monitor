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

  string path = (Path::basePath() + pid + Path::statusPath());

  // Open stream
  ifstream stream = Util::getStream(path, stream);

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

/*
string ProcessParser::getVmsSize(string pid)
{
    string line;
    //Declaring search attribute for file
    string name = "VmData";
    string value;
    float result;
    // Opening stream for specific file
    ifstream stream = Util::getStream((Path::basePath() + pid +
Path::statusPath())); while(std::getline(stream, line)){
        // Searching line by line
        if (line.compare(0, name.size(),name) == 0) {
            // slicing string line on ws for values using sstream
            istringstream buf(line);
            istream_iterator<string> beg(buf), end;
            vector<string> values(beg, end);
            //conversion kB -> GB
            result = (stof(values[1])/float(1024*1024));
            break;
        }
    }
    return to_string(result);
}
 */