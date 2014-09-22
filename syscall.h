#pragma once

#include <string>
#include <vector>

class syscall
{
public:
  int number;
  std::string name;
  std::vector<unsigned int> input_handles;
  std::vector<unsigned int> output_handles;

public:
  syscall(int i_number, const std::string& i_name);
  ~syscall(void);
};

bool operator ==(syscall& lhs, syscall& rhs);
