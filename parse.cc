/* parse.cc */

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <memory>
#include <sstream>
#include <algorithm>

#include "syscall.h"

/* exported functions */
std::vector< std::shared_ptr<syscall> > load_syscall_table(const std::string&);
std::string lookup_syscall_name(std::vector< std::shared_ptr<syscall> >&, int);
int lookup_syscall_number(std::vector< std::shared_ptr<syscall> > &syscall_table, 
  std::string &syscall_name);

  /* ============================================================================
  * parse a syscall table.
  * some codes are copied from: 
  * http://stackoverflow.com/questions/7868936/c-read-file-line-by-line
  * ========================================================================== */
  std::vector< std::shared_ptr<syscall> > load_syscall_table(const std::string &syscall_table_file_name)
{
  // initialize a vector of syscall's smart pointers 
  std::vector< std::shared_ptr<syscall> > syscall_table;

  // open file the syscall table file
  std::ifstream syscall_table_file(syscall_table_file_name);
  if (syscall_table_file.is_open()) {
    std::string current_line;

    // read it line by line
    while (std::getline(syscall_table_file, current_line)) {
      std::istringstream iss(current_line);
      std::string name = ""; int number = 0;

      // parse the current line
      iss >> name >> std::hex >> number;

      // create a smart pointer from parsed data and push it into the vector
      std::shared_ptr<syscall> p_syscall(new syscall(number, name));
      syscall_table.push_back(p_syscall);
    }

    // remember to close file
    syscall_table_file.close();
  }
  else std::cerr << "Open syscall table error, continue running without translator." 
    << std::endl;

  return syscall_table;
}

/* ============================================================================
* lookup the syscall name given its number
* ========================================================================== */
std::string lookup_syscall_name(std::vector< std::shared_ptr<syscall> > &syscall_table, 
  int syscall_number)
{
  std::vector< std::shared_ptr<syscall> >::iterator iter_syscall = syscall_table.begin();
  do {
    if ((*iter_syscall)->number == syscall_number) break;
    else iter_syscall++;
  }
  while (iter_syscall != syscall_table.end());

  if (iter_syscall != syscall_table.end()) return (*iter_syscall)->name;
  else return "Unknow";
}

/* ============================================================================
* lookup the syscall number given its name
* ========================================================================== */
int lookup_syscall_number(std::vector< std::shared_ptr<syscall> > &syscall_table, 
  std::string &syscall_name) 
{
  std::vector< std::shared_ptr<syscall> >::iterator iter_syscall = syscall_table.begin();
  do {
    if ((*iter_syscall)->name == syscall_name) break;
    else iter_syscall++;
  }
  while (iter_syscall != syscall_table.end());

  if (iter_syscall != syscall_table.end()) return (*iter_syscall)->number;
  else return -1;
}
