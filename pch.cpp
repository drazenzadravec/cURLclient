// pch.cpp: source file corresponding to the pre-compiled header

#include "pch.h"

/// <summary>
/// split string
/// </summary>
/// <param name="str">The text</param>
/// <param name="delimiter">The delimiter</param>
/// <returns>Vector of split string</returns>
static std::vector<std::string> split_string(std::string& str, const std::string delimiter)
{
	size_t pos_start = 0, pos_end, delim_len = delimiter.length();
	std::string token;
	std::vector<std::string> res;

	while ((pos_end = str.find(delimiter, pos_start)) != std::string::npos) {
		token = str.substr(pos_start, pos_end - pos_start);
		pos_start = pos_end + delim_len;
		res.push_back(token);
	}

	res.push_back(str.substr(pos_start));
	return res;
}

/// <summary>
/// trim left front
/// </summary>
/// <param name="source">the source</param>
/// <returns>the trimmed string</returns>
static std::string left_trim(const char* source)
{
	const char* trim = "";
	std::string s(source);
	s.erase(0, s.find_first_not_of(trim));
	return std::string(s.c_str());
}

/// <summary>
/// trim right end
/// </summary>
/// <param name="source">the source</param>
/// <returns>the trimmed string</returns>
static std::string right_trim(const char* source)
{
	const char* trim = "";
	std::string s(source);
	s.erase(s.find_last_not_of(trim) + 1);
	return std::string(s.c_str());
}

/// <summary>
/// trim both front and end
/// </summary>
/// <param name="source">the source</param>
/// <returns>the trimmed string</returns>
static std::string both_trim(const char* source)
{
	return left_trim(right_trim(source).c_str());
}

/// <summary>
/// trim left front
/// </summary>
/// <param name="source">the source</param>
/// <param name="trim">the trim value</param>
/// <returns>the trimmed string</returns>
static std::string left_trim(const char* source, const char* trim)
{
	std::string s(source);
	s.erase(0, s.find_first_not_of(trim));
	return std::string(s.c_str());
}

/// <summary>
/// trim right end
/// </summary>
/// <param name="source">the source</param>
/// <param name="trim">the trim value</param>
/// <returns>the trimmed string</returns>
static std::string right_trim(const char* source, const char* trim)
{
	std::string s(source);
	s.erase(s.find_last_not_of(trim) + 1);
	return std::string(s.c_str());
}

/// <summary>
/// trim both front and end
/// </summary>
/// <param name="source">the source</param>
/// <param name="trim">the trim value</param>
/// <returns>the trimmed string</returns>
static std::string both_trim(const char* source, const char* trim)
{
	return left_trim(right_trim(source, trim).c_str(), trim);
}