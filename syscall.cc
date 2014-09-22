#include "syscall.h"

syscall::syscall(int i_number, const std::string& i_name)
{
  this->number = i_number; 
  this->name = i_name;
}

syscall::~syscall(void)
{
}

bool operator ==(syscall& lhs, syscall& rhs)
{
  if (lhs.number == rhs.number) return true;
  else return false;
}