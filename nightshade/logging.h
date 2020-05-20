
#include <string>

#include <iomanip>
#include <iostream>

namespace std
{
std::string to_string(WCHAR *str)
{
  std::wstring ws(str);
  return std::string(ws.begin(), ws.end());
}

std::string to_string(const char *str) { return std::string(str); }
} // namespace std

namespace ns
{
template <typename... T> void log(T... x)
{
  std::ostringstream ss;
  time_t t = std::time(0);
  ss << std::setw(10) << std::this_thread::get_id() << " ";
  ss << std::setw(10) << std::put_time(std::localtime(&t), "%H-%M-%S: ")
     << std::left;
  (ss << ... << (x));
  ss << '\n';

  std::cout << ss.str();
};

template <typename T, typename... Ts>
void format_(
    std::stringstream &ss,
    std::string &format_template,
    size_t& offset,
    T &&arg,
    Ts &&... args)
{
  auto start = format_template.find('{', offset);
  auto end = format_template.find('}', start);
  if (auto has_variable =
          start != std::string::npos && end != std::string::npos;
      has_variable)
  {
    ss << format_template.substr(offset + 1, start - (offset + 1));
    ss << std::to_string(arg);
    format_(ss, format_template, end, args...);
  }
  offset = end;
}

template <typename T>
void format_(
    std::stringstream &ss,
    std::string &format_template,
    size_t& offset,
    T &&arg)
{
  auto start = format_template.find('{', offset);
  auto end = format_template.find('}', start);
  if (auto has_variable =
          start != std::string::npos && end != std::string::npos;
      has_variable)
  {
    ss << format_template.substr(offset + 1, start - (offset + 1));
    ss << std::to_string(arg);
  }
  offset = end;
}

void format_(
    std::stringstream &ss,
    std::string &format_template,
    size_t &offset)
{
}


template <typename T, typename... Ts>
std::string format(std::string format_template, T &&arg, Ts &&... args)
{
  std::stringstream ss;
  auto start = format_template.find('{');
  auto end = format_template.find('}', start);

  if (auto has_variable =
          start != std::string::npos && end != std::string::npos;
      has_variable)
  {
    ss << format_template.substr(0, start);
    ss << std::to_string(arg);
    format_(ss, format_template, end, args...);
    ss << format_template.substr(end + 1, format_template.size());
  }
  else
  {
    ss << format_template;
  }
  return ss.str();
}


} // namespace ns
