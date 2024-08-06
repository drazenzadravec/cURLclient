
#include "pch.h"
#include "CurlClient.h"

#include <curl/curl.h>

using namespace Nequeo::Net;

/// <summary>
/// Write Callback
/// </summary>
/// <param name="contents">the contents</param>
/// <param name="size">the size</param>
/// <param name="nmemb">the size</param>
/// <param name="data">the data</param>
/// <returns>the data size</returns>
static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* data)
{
	((std::string*)data)->append((char*)contents, size * nmemb);
	return size * nmemb;
}

/// <summary>
/// Write Header Callback
/// </summary>
/// <param name="contents">the contents</param>
/// <param name="size">the size</param>
/// <param name="nmemb">the size</param>
/// <param name="data">the data</param>
/// <returns>the data size</returns>
static size_t WriteHeaderCallback(char* contents, size_t size, size_t nmemb, void* data)
{
	((std::string*)data)->append((char*)contents, size * nmemb);
	return size * nmemb;
}

///	<summary>
///	cURL client.
///	</summary>
CurlClient::CurlClient() :
	_disposed(false), _verify_peer(false), _verify_common_name(false), _check_existence(false)
{
}

///	<summary>
///	cURL client.
///	</summary>
CurlClient::~CurlClient()
{
	if (!_disposed)
	{
		_disposed = true;
	}
}

/// <summary>
/// Verify the peer in ssl handshake, set true to verify, false to bypass.
/// </summary>
/// <param name="verifyPeer">true to verify peer: else false.</param>
void CurlClient::SetVerifyPeer(bool verifyPeer)
{
	_verify_peer = verifyPeer;
}

/// <summary>
/// Verify the Common name from the peer certificate in ssl
/// handshake, set true to check existence, true to ensure that it matches the
/// provided hostname.
/// </summary>
/// <param name="checkExistence">true to check existence: else false.</param>
/// <param name="verifyCommonName">true to verify common name: else false.</param>
void CurlClient::SetVerifyCommonName(bool checkExistence, bool verifyCommonName)
{
	_check_existence = checkExistence;
	_verify_common_name = verifyCommonName;
}

/// <summary>
/// make options request.
/// </summary>
/// <param name="url">the URL</param>
/// <param name="responseBody">The response body</param>
/// <param name="responseHeaders">The response headers</param>
/// <returns>true if success: else false</returns>
bool CurlClient::Options(const std::string& url, std::string* responseBody, std::string* responseHeaders) const
{
	bool result = false;
	CURL* curl;
	CURLcode res;
	std::string readBuffer;
	std::string readHeaders;

	// the url
	auto const& url_request = url;

	// make request.
	curl = curl_easy_init();
	if (curl) {

		// add curl options
		curl_easy_setopt(curl, CURLOPT_URL, url_request.c_str());
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
		curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, WriteHeaderCallback);
		curl_easy_setopt(curl, CURLOPT_WRITEHEADER, &readHeaders);
		curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, (long)CURL_HTTP_VERSION_2TLS);

		// 1L to verify 0L to not verify.
		// Set if we should verify the peer in ssl handshake, set 1 to verify.
		if (_verify_peer)
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
		}
		else
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
		}

		// 1L to verify 0L to not verify.
		// Set if we should verify the Common name from the peer certificate in ssl
		// handshake, set 1 to check existence, 2 to ensure that it matches the
		// provided hostname.
		if (_verify_common_name)
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
		}
		else if (_check_existence)
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 1L);
		}
		else
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
		}

		curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "OPTIONS");

		// make the request.
		res = curl_easy_perform(curl);
		if (res != CURLE_OK)
		{
			result = false;
		}
		else
		{
			result = true;
		}

		// clean up
		curl_easy_cleanup(curl);

		// assign result.
		*responseBody = readBuffer;
		*responseHeaders = readHeaders;
	}
	else
	{
		result = false;
	}

	// return
	return result;
}

/// <summary>
/// make options request.
/// </summary>
/// <param name="url">the URL</param>
/// <param name="requestHeaders">the request headers</param>
/// <param name="responseBody">The response body</param>
/// <param name="responseHeaders">The response headers</param>
/// <returns>true if success: else false</returns>
bool CurlClient::Options(const std::string& url, const std::map<std::string, std::string>& requestHeaders,
	std::string* responseBody, std::string* responseHeaders) const
{
	bool result = false;
	CURL* curl;
	CURLcode res;
	std::string readBuffer;
	std::string readHeaders;

	// the url
	auto const& url_request = url;
	struct curl_slist* headers = NULL;

	curl = curl_easy_init();
	if (curl) {

		// add curl options
		curl_easy_setopt(curl, CURLOPT_URL, url_request.c_str());
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
		curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, WriteHeaderCallback);
		curl_easy_setopt(curl, CURLOPT_WRITEHEADER, &readHeaders);
		curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, (long)CURL_HTTP_VERSION_2TLS);

		// 1L to verify 0L to not verify.
		// Set if we should verify the peer in ssl handshake, set 1 to verify.
		if (_verify_peer)
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
		}
		else
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
		}

		// 1L to verify 0L to not verify.
		// Set if we should verify the Common name from the peer certificate in ssl
		// handshake, set 1 to check existence, 2 to ensure that it matches the
		// provided hostname.
		if (_verify_common_name)
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
		}
		else if (_check_existence)
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 1L);
		}
		else
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
		}

		curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "OPTIONS");

		// for each request header.
		for (const auto& header : requestHeaders)
		{
			// create header name and value.
			std::string headerName(header.first);
			std::string headerValue(header.second);
			std::string header_v = headerName + headerValue;

			// add the header to the header list
			headers = curl_slist_append(headers, header_v.c_str());
		}

		// add the headers
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

		// make the request.
		res = curl_easy_perform(curl);
		if (res != CURLE_OK)
		{
			result = false;
		}
		else
		{
			result = true;
		}

		// clean up
		curl_slist_free_all(headers);
		curl_easy_cleanup(curl);

		// assign result.
		*responseBody = readBuffer;
		*responseHeaders = readHeaders;
	}
	else
	{
		result = false;
	}

	// return
	return result;
}


/// <summary>
/// make head request.
/// </summary>
/// <param name="url">the URL</param>
/// <param name="responseHeaders">The response headers</param>
/// <returns>true if success: else false</returns>
bool CurlClient::Head(const std::string& url, std::string* responseHeaders) const
{
	bool result = false;
	CURL* curl;
	CURLcode res;
	std::string readBuffer;
	std::string readHeaders;

	// the url
	auto const& url_request = url;

	// make request.
	curl = curl_easy_init();
	if (curl) {

		// add curl options
		curl_easy_setopt(curl, CURLOPT_URL, url_request.c_str());
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
		curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, WriteHeaderCallback);
		curl_easy_setopt(curl, CURLOPT_WRITEHEADER, &readHeaders);
		curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, (long)CURL_HTTP_VERSION_2TLS);

		// 1L to verify 0L to not verify.
		// Set if we should verify the peer in ssl handshake, set 1 to verify.
		if (_verify_peer)
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
		}
		else
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
		}

		// 1L to verify 0L to not verify.
		// Set if we should verify the Common name from the peer certificate in ssl
		// handshake, set 1 to check existence, 2 to ensure that it matches the
		// provided hostname.
		if (_verify_common_name)
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
		}
		else if (_check_existence)
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 1L);
		}
		else
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
		}

		curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "HEAD");

		// make the request.
		res = curl_easy_perform(curl);
		if (res != CURLE_OK)
		{
			result = false;
		}
		else
		{
			result = true;
		}

		// clean up
		curl_easy_cleanup(curl);

		// assign result.
		*responseHeaders = readHeaders;
	}
	else
	{
		result = false;
	}

	// return
	return result;
}

/// <summary>
/// make head request.
/// </summary>
/// <param name="url">the URL</param>
/// <param name="requestHeaders">the request headers</param>
/// <param name="responseHeaders">The response headers</param>
/// <returns>true if success: else false</returns>
bool CurlClient::Head(const std::string& url, const std::map<std::string, std::string>& requestHeaders, std::string* responseHeaders) const
{
	bool result = false;
	CURL* curl;
	CURLcode res;
	std::string readBuffer;
	std::string readHeaders;

	// the url
	auto const& url_request = url;
	struct curl_slist* headers = NULL;

	curl = curl_easy_init();
	if (curl) {

		// add curl options
		curl_easy_setopt(curl, CURLOPT_URL, url_request.c_str());
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
		curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, WriteHeaderCallback);
		curl_easy_setopt(curl, CURLOPT_WRITEHEADER, &readHeaders);
		curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, (long)CURL_HTTP_VERSION_2TLS);

		// 1L to verify 0L to not verify.
		// Set if we should verify the peer in ssl handshake, set 1 to verify.
		if (_verify_peer)
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
		}
		else
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
		}

		// 1L to verify 0L to not verify.
		// Set if we should verify the Common name from the peer certificate in ssl
		// handshake, set 1 to check existence, 2 to ensure that it matches the
		// provided hostname.
		if (_verify_common_name)
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
		}
		else if (_check_existence)
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 1L);
		}
		else
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
		}

		// for each request header.
		for (const auto& header : requestHeaders)
		{
			// create header name and value.
			std::string headerName(header.first);
			std::string headerValue(header.second);
			std::string header_v = headerName + headerValue;

			// add the header to the header list
			headers = curl_slist_append(headers, header_v.c_str());
		}

		// add the headers
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
		curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "HEAD");

		// make the request.
		res = curl_easy_perform(curl);
		if (res != CURLE_OK)
		{
			result = false;
		}
		else
		{
			result = true;
		}

		// clean up
		curl_slist_free_all(headers);
		curl_easy_cleanup(curl);

		// assign result.
		*responseHeaders = readHeaders;
	}
	else
	{
		result = false;
	}

	// return
	return result;
}

/// <summary>
/// make get request.
/// </summary>
/// <param name="url">the URL</param>
/// <param name="responseBody">The response body</param>
/// <param name="responseHeaders">The response headers</param>
/// <returns>true if success: else false</returns>
bool CurlClient::Get(const std::string& url, std::string* responseBody, std::string* responseHeaders) const
{
	bool result = false;
	CURL* curl;
	CURLcode res;
	std::string readBuffer;
	std::string readHeaders;

	// the url
	auto const& url_request = url;

	// make request.
	curl = curl_easy_init();
	if (curl) {

		// add curl options
		curl_easy_setopt(curl, CURLOPT_URL, url_request.c_str());
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
		curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, WriteHeaderCallback);
		curl_easy_setopt(curl, CURLOPT_WRITEHEADER, &readHeaders);
		curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, (long)CURL_HTTP_VERSION_2TLS);

		// 1L to verify 0L to not verify.
		// Set if we should verify the peer in ssl handshake, set 1 to verify.
		if (_verify_peer)
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
		}
		else
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
		}

		// 1L to verify 0L to not verify.
		// Set if we should verify the Common name from the peer certificate in ssl
		// handshake, set 1 to check existence, 2 to ensure that it matches the
		// provided hostname.
		if (_verify_common_name)
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
		}
		else if (_check_existence)
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 1L);
		}
		else
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
		}

		// make the request.
		res = curl_easy_perform(curl);
		if (res != CURLE_OK)
		{
			result = false;
		}
		else
		{
			result = true;
		}

		// clean up
		curl_easy_cleanup(curl);

		// assign result.
		*responseBody = readBuffer;
		*responseHeaders = readHeaders;
	}
	else
	{
		result = false;
	}

	// return
	return result;
}

/// <summary>
/// make get request.
/// </summary>
/// <param name="url">the URL</param>
/// <param name="requestHeaders">the request headers</param>
/// <param name="responseBody">The response body</param>
/// <param name="responseHeaders">The response headers</param>
/// <returns>true if success: else false</returns>
bool CurlClient::Get(const std::string& url, const std::map<std::string, std::string>& requestHeaders,
	std::string* responseBody, std::string* responseHeaders) const
{
	bool result = false;
	CURL* curl;
	CURLcode res;
	std::string readBuffer;
	std::string readHeaders;

	// the url
	auto const& url_request = url;
	struct curl_slist* headers = NULL;

	curl = curl_easy_init();
	if (curl) {

		// add curl options
		curl_easy_setopt(curl, CURLOPT_URL, url_request.c_str());
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
		curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, WriteHeaderCallback);
		curl_easy_setopt(curl, CURLOPT_WRITEHEADER, &readHeaders);
		curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, (long)CURL_HTTP_VERSION_2TLS);

		// 1L to verify 0L to not verify.
		// Set if we should verify the peer in ssl handshake, set 1 to verify.
		if (_verify_peer)
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
		}
		else
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
		}

		// 1L to verify 0L to not verify.
		// Set if we should verify the Common name from the peer certificate in ssl
		// handshake, set 1 to check existence, 2 to ensure that it matches the
		// provided hostname.
		if (_verify_common_name)
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
		}
		else if (_check_existence)
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 1L);
		}
		else
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
		}

		// for each request header.
		for (const auto& header : requestHeaders)
		{
			// create header name and value.
			std::string headerName(header.first);
			std::string headerValue(header.second);
			std::string header_v = headerName + headerValue;

			// add the header to the header list
			headers = curl_slist_append(headers, header_v.c_str());
		}

		// add the headers
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

		// make the request.
		res = curl_easy_perform(curl);
		if (res != CURLE_OK)
		{
			result = false;
		}
		else
		{
			result = true;
		}

		// clean up
		curl_slist_free_all(headers);
		curl_easy_cleanup(curl);

		// assign result.
		*responseBody = readBuffer;
		*responseHeaders = readHeaders;
	}
	else
	{
		result = false;
	}

	// return
	return result;
}

/// <summary>
/// make post request
/// </summary>
/// <param name="url">the URL</param>
/// <param name="requestBody">The request body</param>
/// <param name="requestContentType">The request content type</param>
/// <param name="responseBody">The response body</param>
/// <param name="responseHeaders">The response headers</param>
/// <returns>true if success: else false</returns>
bool CurlClient::Post(const std::string& url, const std::string& requestBody, const std::string& requestContentType,
	std::string* responseBody, std::string* responseHeaders) const
{
	bool result = false;
	CURL* curl;
	CURLcode res;
	std::string readBuffer;
	std::string readHeaders;

	// the url
	auto const& url_request = url;
	struct curl_slist* headers = NULL;

	auto& body_request = requestBody;
	std::string body_content_type = "Content-Type: " + requestContentType;

	curl = curl_easy_init();
	if (curl) {

		// add curl options
		curl_easy_setopt(curl, CURLOPT_URL, url_request.c_str());
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
		curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, WriteHeaderCallback);
		curl_easy_setopt(curl, CURLOPT_WRITEHEADER, &readHeaders);
		curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, (long)CURL_HTTP_VERSION_2TLS);

		// 1L to verify 0L to not verify.
		// Set if we should verify the peer in ssl handshake, set 1 to verify.
		if (_verify_peer)
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
		}
		else
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
		}

		// 1L to verify 0L to not verify.
		// Set if we should verify the Common name from the peer certificate in ssl
		// handshake, set 1 to check existence, 2 to ensure that it matches the
		// provided hostname.
		if (_verify_common_name)
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
		}
		else if (_check_existence)
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 1L);
		}
		else
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
		}

		// post
		std::string post(body_request);
		std::string postLength = std::to_string(post.size());
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body_request.c_str());

		std::string contentTypeNme("Content-Type: ");
		std::string contentTypeArg(requestContentType);
		body_content_type = contentTypeNme + contentTypeArg;

		std::string contentLength = "Content-Length: " + postLength;
		std::string contentType = body_content_type;
		headers = curl_slist_append(headers, contentType.c_str());
		headers = curl_slist_append(headers, contentLength.c_str());
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

		// make the request.
		res = curl_easy_perform(curl);
		if (res != CURLE_OK)
		{
			result = false;
		}
		else
		{
			result = true;
		}

		// clean up
		curl_slist_free_all(headers);
		curl_easy_cleanup(curl);

		// assign result.
		*responseBody = readBuffer;
		*responseHeaders = readHeaders;
	}
	else
	{
		result = false;
	}

	// return
	return result;
}

/// <summary>
/// make post request
/// </summary>
/// <param name="url">the URL</param>
/// <param name="requestBody">The request body</param>
/// <param name="requestContentType">The request content type</param>
/// <param name="requestHeaders">the request headers</param>
/// <param name="responseBody">The response body</param>
/// <param name="responseHeaders">The response headers</param>
/// <returns>true if success: else false</returns>
bool CurlClient::Post(const std::string& url, const std::string& requestBody, const std::string& requestContentType,
	const std::map<std::string, std::string>& requestHeaders, std::string* responseBody, std::string* responseHeaders) const
{
	bool result = false;
	CURL* curl;
	CURLcode res;
	std::string readBuffer;
	std::string readHeaders;

	// the url
	auto const& url_request = url;
	struct curl_slist* headers = NULL;

	auto& body_request = requestBody;
	std::string body_content_type = "Content-Type: " + requestContentType;

	curl = curl_easy_init();
	if (curl) {

		// add curl options
		curl_easy_setopt(curl, CURLOPT_URL, url_request.c_str());
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
		curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, WriteHeaderCallback);
		curl_easy_setopt(curl, CURLOPT_WRITEHEADER, &readHeaders);
		curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, (long)CURL_HTTP_VERSION_2TLS);

		// 1L to verify 0L to not verify.
		// Set if we should verify the peer in ssl handshake, set 1 to verify.
		if (_verify_peer)
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
		}
		else
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
		}

		// 1L to verify 0L to not verify.
		// Set if we should verify the Common name from the peer certificate in ssl
		// handshake, set 1 to check existence, 2 to ensure that it matches the
		// provided hostname.
		if (_verify_common_name)
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
		}
		else if (_check_existence)
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 1L);
		}
		else
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
		}

		// post
		std::string post(body_request);
		std::string postLength = std::to_string(post.size());
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body_request.c_str());

		// for each request header.
		for (const auto& header : requestHeaders)
		{
			// create header name and value.
			std::string headerName(header.first);
			std::string headerValue(header.second);
			std::string header_v = headerName + headerValue;

			// add the header to the header list
			headers = curl_slist_append(headers, header_v.c_str());
		}

		std::string contentTypeNme("Content-Type: ");
		std::string contentTypeArg(requestContentType);
		body_content_type = contentTypeNme + contentTypeArg;

		std::string contentLength = "Content-Length: " + postLength;
		std::string contentType = body_content_type;
		headers = curl_slist_append(headers, contentType.c_str());
		headers = curl_slist_append(headers, contentLength.c_str());
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

		// make the request.
		res = curl_easy_perform(curl);
		if (res != CURLE_OK)
		{
			result = false;
		}
		else
		{
			result = true;
		}

		// clean up
		curl_slist_free_all(headers);
		curl_easy_cleanup(curl);

		// assign result.
		*responseBody = readBuffer;
		*responseHeaders = readHeaders;
	}
	else
	{
		result = false;
	}

	// return
	return result;
}

/// <summary>
/// make put request.
/// </summary>
/// <param name="url">the URL</param>
/// <param name="responseBody">The response body</param>
/// <param name="responseHeaders">The response headers</param>
/// <returns>true if success: else false</returns>
bool CurlClient::Put(const std::string& url, std::string* responseBody, std::string* responseHeaders) const
{
	bool result = false;
	CURL* curl;
	CURLcode res;
	std::string readBuffer;
	std::string readHeaders;

	// the url
	auto const& url_request = url;

	// make request.
	curl = curl_easy_init();
	if (curl) {

		// add curl options
		curl_easy_setopt(curl, CURLOPT_URL, url_request.c_str());
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
		curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, WriteHeaderCallback);
		curl_easy_setopt(curl, CURLOPT_WRITEHEADER, &readHeaders);
		curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, (long)CURL_HTTP_VERSION_2TLS);

		// 1L to verify 0L to not verify.
		// Set if we should verify the peer in ssl handshake, set 1 to verify.
		if (_verify_peer)
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
		}
		else
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
		}

		// 1L to verify 0L to not verify.
		// Set if we should verify the Common name from the peer certificate in ssl
		// handshake, set 1 to check existence, 2 to ensure that it matches the
		// provided hostname.
		if (_verify_common_name)
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
		}
		else if (_check_existence)
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 1L);
		}
		else
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
		}

		curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");

		// make the request.
		res = curl_easy_perform(curl);
		if (res != CURLE_OK)
		{
			result = false;
		}
		else
		{
			result = true;
		}

		// clean up
		curl_easy_cleanup(curl);

		// assign result.
		*responseBody = readBuffer;
		*responseHeaders = readHeaders;
	}
	else
	{
		result = false;
	}

	// return
	return result;
}

/// <summary>
/// make put request.
/// </summary>
/// <param name="url">the URL</param>
/// <param name="requestHeaders">the request headers</param>
/// <param name="responseBody">The response body</param>
/// <param name="responseHeaders">The response headers</param>
/// <returns>true if success: else false</returns>
bool CurlClient::Put(const std::string& url, const std::map<std::string,
	std::string>& requestHeaders, std::string* responseBody, std::string* responseHeaders) const
{
	bool result = false;
	CURL* curl;
	CURLcode res;
	std::string readBuffer;
	std::string readHeaders;

	// the url
	auto const& url_request = url;
	struct curl_slist* headers = NULL;

	curl = curl_easy_init();
	if (curl) {

		// add curl options
		curl_easy_setopt(curl, CURLOPT_URL, url_request.c_str());
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
		curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, WriteHeaderCallback);
		curl_easy_setopt(curl, CURLOPT_WRITEHEADER, &readHeaders);
		curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, (long)CURL_HTTP_VERSION_2TLS);

		// 1L to verify 0L to not verify.
		// Set if we should verify the peer in ssl handshake, set 1 to verify.
		if (_verify_peer)
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
		}
		else
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
		}

		// 1L to verify 0L to not verify.
		// Set if we should verify the Common name from the peer certificate in ssl
		// handshake, set 1 to check existence, 2 to ensure that it matches the
		// provided hostname.
		if (_verify_common_name)
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
		}
		else if (_check_existence)
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 1L);
		}
		else
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
		}

		curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");

		// for each request header.
		for (const auto& header : requestHeaders)
		{
			// create header name and value.
			std::string headerName(header.first);
			std::string headerValue(header.second);
			std::string header_v = headerName + headerValue;

			// add the header to the header list
			headers = curl_slist_append(headers, header_v.c_str());
		}

		// add the headers
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

		// make the request.
		res = curl_easy_perform(curl);
		if (res != CURLE_OK)
		{
			result = false;
		}
		else
		{
			result = true;
		}

		// clean up
		curl_slist_free_all(headers);
		curl_easy_cleanup(curl);

		// assign result.
		*responseBody = readBuffer;
		*responseHeaders = readHeaders;
	}
	else
	{
		result = false;
	}

	// return
	return result;
}

/// <summary>
/// make put request
/// </summary>
/// <param name="url">the URL</param>
/// <param name="requestBody">The request body</param>
/// <param name="requestContentType">The request content type</param>
/// <param name="responseBody">The response body</param>
/// <param name="responseHeaders">The response headers</param>
/// <returns>true if success: else false</returns>
bool CurlClient::Put(const std::string& url, const std::string& requestBody, const std::string& requestContentType,
	std::string* responseBody, std::string* responseHeaders) const
{
	bool result = false;
	CURL* curl;
	CURLcode res;
	std::string readBuffer;
	std::string readHeaders;

	// the url
	auto const& url_request = url;
	struct curl_slist* headers = NULL;

	auto& body_request = requestBody;
	std::string body_content_type = "Content-Type: " + requestContentType;

	curl = curl_easy_init();
	if (curl) {

		// add curl options
		curl_easy_setopt(curl, CURLOPT_URL, url_request.c_str());
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
		curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, WriteHeaderCallback);
		curl_easy_setopt(curl, CURLOPT_WRITEHEADER, &readHeaders);
		curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, (long)CURL_HTTP_VERSION_2TLS);

		// 1L to verify 0L to not verify.
		// Set if we should verify the peer in ssl handshake, set 1 to verify.
		if (_verify_peer)
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
		}
		else
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
		}

		// 1L to verify 0L to not verify.
		// Set if we should verify the Common name from the peer certificate in ssl
		// handshake, set 1 to check existence, 2 to ensure that it matches the
		// provided hostname.
		if (_verify_common_name)
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
		}
		else if (_check_existence)
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 1L);
		}
		else
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
		}

		// post
		std::string post(body_request);
		std::string postLength = std::to_string(post.size());
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body_request.c_str());
		curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");

		std::string contentTypeNme("Content-Type: ");
		std::string contentTypeArg(requestContentType);
		body_content_type = contentTypeNme + contentTypeArg;

		std::string contentLength = "Content-Length: " + postLength;
		std::string contentType = body_content_type;
		headers = curl_slist_append(headers, contentType.c_str());
		headers = curl_slist_append(headers, contentLength.c_str());
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

		// make the request.
		res = curl_easy_perform(curl);
		if (res != CURLE_OK)
		{
			result = false;
		}
		else
		{
			result = true;
		}

		// clean up
		curl_slist_free_all(headers);
		curl_easy_cleanup(curl);

		// assign result.
		*responseBody = readBuffer;
		*responseHeaders = readHeaders;
	}
	else
	{
		result = false;
	}

	// return
	return result;
}

/// <summary>
/// make put request
/// </summary>
/// <param name="url">the URL</param>
/// <param name="requestBody">The request body</param>
/// <param name="requestContentType">The request content type</param>
/// <param name="requestHeaders">the request headers</param>
/// <param name="responseBody">The response body</param>
/// <param name="responseHeaders">The response headers</param>
/// <returns>true if success: else false</returns>
bool CurlClient::Put(const std::string& url, const std::string& requestBody, const std::string& requestContentType,
	const std::map<std::string, std::string>& requestHeaders, std::string* responseBody, std::string* responseHeaders) const
{
	bool result = false;
	CURL* curl;
	CURLcode res;
	std::string readBuffer;
	std::string readHeaders;

	// the url
	auto const& url_request = url;
	struct curl_slist* headers = NULL;

	auto& body_request = requestBody;
	std::string body_content_type = "Content-Type: " + requestContentType;

	curl = curl_easy_init();
	if (curl) {

		// add curl options
		curl_easy_setopt(curl, CURLOPT_URL, url_request.c_str());
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
		curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, WriteHeaderCallback);
		curl_easy_setopt(curl, CURLOPT_WRITEHEADER, &readHeaders);
		curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, (long)CURL_HTTP_VERSION_2TLS);

		// 1L to verify 0L to not verify.
		// Set if we should verify the peer in ssl handshake, set 1 to verify.
		if (_verify_peer)
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
		}
		else
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
		}

		// 1L to verify 0L to not verify.
		// Set if we should verify the Common name from the peer certificate in ssl
		// handshake, set 1 to check existence, 2 to ensure that it matches the
		// provided hostname.
		if (_verify_common_name)
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
		}
		else if (_check_existence)
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 1L);
		}
		else
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
		}

		// post
		std::string post(body_request);
		std::string postLength = std::to_string(post.size());
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body_request.c_str());
		curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");

		// for each request header.
		for (const auto& header : requestHeaders)
		{
			// create header name and value.
			std::string headerName(header.first);
			std::string headerValue(header.second);
			std::string header_v = headerName + headerValue;

			// add the header to the header list
			headers = curl_slist_append(headers, header_v.c_str());
		}

		std::string contentTypeNme("Content-Type: ");
		std::string contentTypeArg(requestContentType);
		body_content_type = contentTypeNme + contentTypeArg;

		std::string contentLength = "Content-Length: " + postLength;
		std::string contentType = body_content_type;
		headers = curl_slist_append(headers, contentType.c_str());
		headers = curl_slist_append(headers, contentLength.c_str());
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

		// make the request.
		res = curl_easy_perform(curl);
		if (res != CURLE_OK)
		{
			result = false;
		}
		else
		{
			result = true;
		}

		// clean up
		curl_slist_free_all(headers);
		curl_easy_cleanup(curl);

		// assign result.
		*responseBody = readBuffer;
		*responseHeaders = readHeaders;
	}
	else
	{
		result = false;
	}

	// return
	return result;
}

/// <summary>
/// make delete request.
/// </summary>
/// <param name="url">the URL</param>
/// <param name="responseBody">The response body</param>
/// <param name="responseHeaders">The response headers</param>
/// <returns>true if success: else false</returns>
bool CurlClient::Delete(const std::string& url, std::string* responseBody, std::string* responseHeaders) const
{
	bool result = false;
	CURL* curl;
	CURLcode res;
	std::string readBuffer;
	std::string readHeaders;

	// the url
	auto const& url_request = url;

	// make request.
	curl = curl_easy_init();
	if (curl) {

		// add curl options
		curl_easy_setopt(curl, CURLOPT_URL, url_request.c_str());
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
		curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, WriteHeaderCallback);
		curl_easy_setopt(curl, CURLOPT_WRITEHEADER, &readHeaders);
		curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, (long)CURL_HTTP_VERSION_2TLS);

		// 1L to verify 0L to not verify.
		// Set if we should verify the peer in ssl handshake, set 1 to verify.
		if (_verify_peer)
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
		}
		else
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
		}

		// 1L to verify 0L to not verify.
		// Set if we should verify the Common name from the peer certificate in ssl
		// handshake, set 1 to check existence, 2 to ensure that it matches the
		// provided hostname.
		if (_verify_common_name)
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
		}
		else if (_check_existence)
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 1L);
		}
		else
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
		}

		curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");

		// make the request.
		res = curl_easy_perform(curl);
		if (res != CURLE_OK)
		{
			result = false;
		}
		else
		{
			result = true;
		}

		// clean up
		curl_easy_cleanup(curl);

		// assign result.
		*responseBody = readBuffer;
		*responseHeaders = readHeaders;
	}
	else
	{
		result = false;
	}

	// return
	return result;
}

/// <summary>
/// make delete request.
/// </summary>
/// <param name="url">the URL</param>
/// <param name="requestHeaders">the request headers</param>
/// <param name="responseBody">The response body</param>
/// <param name="responseHeaders">The response headers</param>
/// <returns>true if success: else false</returns>
bool CurlClient::Delete(const std::string& url, const std::map<std::string,
	std::string>& requestHeaders, std::string* responseBody, std::string* responseHeaders) const
{
	bool result = false;
	CURL* curl;
	CURLcode res;
	std::string readBuffer;
	std::string readHeaders;

	// the url
	auto const& url_request = url;
	struct curl_slist* headers = NULL;

	curl = curl_easy_init();
	if (curl) {

		// add curl options
		curl_easy_setopt(curl, CURLOPT_URL, url_request.c_str());
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
		curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, WriteHeaderCallback);
		curl_easy_setopt(curl, CURLOPT_WRITEHEADER, &readHeaders);
		curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, (long)CURL_HTTP_VERSION_2TLS);

		// 1L to verify 0L to not verify.
		// Set if we should verify the peer in ssl handshake, set 1 to verify.
		if (_verify_peer)
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
		}
		else
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
		}

		// 1L to verify 0L to not verify.
		// Set if we should verify the Common name from the peer certificate in ssl
		// handshake, set 1 to check existence, 2 to ensure that it matches the
		// provided hostname.
		if (_verify_common_name)
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
		}
		else if (_check_existence)
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 1L);
		}
		else
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
		}

		curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");

		// for each request header.
		for (const auto& header : requestHeaders)
		{
			// create header name and value.
			std::string headerName(header.first);
			std::string headerValue(header.second);
			std::string header_v = headerName + headerValue;

			// add the header to the header list
			headers = curl_slist_append(headers, header_v.c_str());
		}

		// add the headers
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

		// make the request.
		res = curl_easy_perform(curl);
		if (res != CURLE_OK)
		{
			result = false;
		}
		else
		{
			result = true;
		}

		// clean up
		curl_slist_free_all(headers);
		curl_easy_cleanup(curl);

		// assign result.
		*responseBody = readBuffer;
		*responseHeaders = readHeaders;
	}
	else
	{
		result = false;
	}

	// return
	return result;
}

/// <summary>
/// make delete request
/// </summary>
/// <param name="url">the URL</param>
/// <param name="requestBody">The request body</param>
/// <param name="requestContentType">The request content type</param>
/// <param name="responseBody">The response body</param>
/// <param name="responseHeaders">The response headers</param>
/// <returns>true if success: else false</returns>
bool CurlClient::Delete(const std::string& url, const std::string& requestBody, const std::string& requestContentType,
	std::string* responseBody, std::string* responseHeaders) const
{
	bool result = false;
	CURL* curl;
	CURLcode res;
	std::string readBuffer;
	std::string readHeaders;

	// the url
	auto const& url_request = url;
	struct curl_slist* headers = NULL;

	auto& body_request = requestBody;
	std::string body_content_type = "Content-Type: " + requestContentType;

	curl = curl_easy_init();
	if (curl) {

		// add curl options
		curl_easy_setopt(curl, CURLOPT_URL, url_request.c_str());
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
		curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, WriteHeaderCallback);
		curl_easy_setopt(curl, CURLOPT_WRITEHEADER, &readHeaders);
		curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, (long)CURL_HTTP_VERSION_2TLS);

		// 1L to verify 0L to not verify.
		// Set if we should verify the peer in ssl handshake, set 1 to verify.
		if (_verify_peer)
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
		}
		else
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
		}

		// 1L to verify 0L to not verify.
		// Set if we should verify the Common name from the peer certificate in ssl
		// handshake, set 1 to check existence, 2 to ensure that it matches the
		// provided hostname.
		if (_verify_common_name)
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
		}
		else if (_check_existence)
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 1L);
		}
		else
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
		}

		// post
		std::string post(body_request);
		std::string postLength = std::to_string(post.size());
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body_request.c_str());
		curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");

		std::string contentTypeNme("Content-Type: ");
		std::string contentTypeArg(requestContentType);
		body_content_type = contentTypeNme + contentTypeArg;

		std::string contentLength = "Content-Length: " + postLength;
		std::string contentType = body_content_type;
		headers = curl_slist_append(headers, contentType.c_str());
		headers = curl_slist_append(headers, contentLength.c_str());
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

		// make the request.
		res = curl_easy_perform(curl);
		if (res != CURLE_OK)
		{
			result = false;
		}
		else
		{
			result = true;
		}

		// clean up
		curl_slist_free_all(headers);
		curl_easy_cleanup(curl);

		// assign result.
		*responseBody = readBuffer;
		*responseHeaders = readHeaders;
	}
	else
	{
		result = false;
	}

	// return
	return result;
}

/// <summary>
/// make delete request
/// </summary>
/// <param name="url">the URL</param>
/// <param name="requestBody">The request body</param>
/// <param name="requestContentType">The request content type</param>
/// <param name="requestHeaders">the request headers</param>
/// <param name="responseBody">The response body</param>
/// <param name="responseHeaders">The response headers</param>
/// <returns>true if success: else false</returns>
bool CurlClient::Delete(const std::string& url, const std::string& requestBody, const std::string& requestContentType,
	const std::map<std::string, std::string>& requestHeaders, std::string* responseBody, std::string* responseHeaders) const
{
	bool result = false;
	CURL* curl;
	CURLcode res;
	std::string readBuffer;
	std::string readHeaders;

	// the url
	auto const& url_request = url;
	struct curl_slist* headers = NULL;

	auto& body_request = requestBody;
	std::string body_content_type = "Content-Type: " + requestContentType;

	curl = curl_easy_init();
	if (curl) {

		// add curl options
		curl_easy_setopt(curl, CURLOPT_URL, url_request.c_str());
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
		curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, WriteHeaderCallback);
		curl_easy_setopt(curl, CURLOPT_WRITEHEADER, &readHeaders);
		curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, (long)CURL_HTTP_VERSION_2TLS);

		// 1L to verify 0L to not verify.
		// Set if we should verify the peer in ssl handshake, set 1 to verify.
		if (_verify_peer)
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
		}
		else
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
		}

		// 1L to verify 0L to not verify.
		// Set if we should verify the Common name from the peer certificate in ssl
		// handshake, set 1 to check existence, 2 to ensure that it matches the
		// provided hostname.
		if (_verify_common_name)
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
		}
		else if (_check_existence)
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 1L);
		}
		else
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
		}

		// post
		std::string post(body_request);
		std::string postLength = std::to_string(post.size());
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body_request.c_str());
		curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");

		// for each request header.
		for (const auto& header : requestHeaders)
		{
			// create header name and value.
			std::string headerName(header.first);
			std::string headerValue(header.second);
			std::string header_v = headerName + headerValue;

			// add the header to the header list
			headers = curl_slist_append(headers, header_v.c_str());
		}

		std::string contentTypeNme("Content-Type: ");
		std::string contentTypeArg(requestContentType);
		body_content_type = contentTypeNme + contentTypeArg;

		std::string contentLength = "Content-Length: " + postLength;
		std::string contentType = body_content_type;
		headers = curl_slist_append(headers, contentType.c_str());
		headers = curl_slist_append(headers, contentLength.c_str());
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

		// make the request.
		res = curl_easy_perform(curl);
		if (res != CURLE_OK)
		{
			result = false;
		}
		else
		{
			result = true;
		}

		// clean up
		curl_slist_free_all(headers);
		curl_easy_cleanup(curl);

		// assign result.
		*responseBody = readBuffer;
		*responseHeaders = readHeaders;
	}
	else
	{
		result = false;
	}

	// return
	return result;
}

/// <summary>
/// make patch request.
/// </summary>
/// <param name="url">the URL</param>
/// <param name="responseBody">The response body</param>
/// <param name="responseHeaders">The response headers</param>
/// <returns>true if success: else false</returns>
bool CurlClient::Patch(const std::string& url, std::string* responseBody, std::string* responseHeaders) const
{
	bool result = false;
	CURL* curl;
	CURLcode res;
	std::string readBuffer;
	std::string readHeaders;

	// the url
	auto const& url_request = url;

	// make request.
	curl = curl_easy_init();
	if (curl) {

		// add curl options
		curl_easy_setopt(curl, CURLOPT_URL, url_request.c_str());
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
		curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, WriteHeaderCallback);
		curl_easy_setopt(curl, CURLOPT_WRITEHEADER, &readHeaders);
		curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, (long)CURL_HTTP_VERSION_2TLS);

		// 1L to verify 0L to not verify.
		// Set if we should verify the peer in ssl handshake, set 1 to verify.
		if (_verify_peer)
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
		}
		else
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
		}

		// 1L to verify 0L to not verify.
		// Set if we should verify the Common name from the peer certificate in ssl
		// handshake, set 1 to check existence, 2 to ensure that it matches the
		// provided hostname.
		if (_verify_common_name)
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
		}
		else if (_check_existence)
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 1L);
		}
		else
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
		}

		curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PATCH");

		// make the request.
		res = curl_easy_perform(curl);
		if (res != CURLE_OK)
		{
			result = false;
		}
		else
		{
			result = true;
		}

		// clean up
		curl_easy_cleanup(curl);

		// assign result.
		*responseBody = readBuffer;
		*responseHeaders = readHeaders;
	}
	else
	{
		result = false;
	}

	// return
	return result;
}

/// <summary>
/// make patch request.
/// </summary>
/// <param name="url">the URL</param>
/// <param name="requestHeaders">the request headers</param>
/// <param name="responseBody">The response body</param>
/// <param name="responseHeaders">The response headers</param>
/// <returns>true if success: else false</returns>
bool CurlClient::Patch(const std::string& url, const std::map<std::string, std::string>& requestHeaders,
	std::string* responseBody, std::string* responseHeaders) const
{
	bool result = false;
	CURL* curl;
	CURLcode res;
	std::string readBuffer;
	std::string readHeaders;

	// the url
	auto const& url_request = url;
	struct curl_slist* headers = NULL;

	curl = curl_easy_init();
	if (curl) {

		// add curl options
		curl_easy_setopt(curl, CURLOPT_URL, url_request.c_str());
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
		curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, WriteHeaderCallback);
		curl_easy_setopt(curl, CURLOPT_WRITEHEADER, &readHeaders);
		curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, (long)CURL_HTTP_VERSION_2TLS);

		// 1L to verify 0L to not verify.
		// Set if we should verify the peer in ssl handshake, set 1 to verify.
		if (_verify_peer)
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
		}
		else
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
		}

		// 1L to verify 0L to not verify.
		// Set if we should verify the Common name from the peer certificate in ssl
		// handshake, set 1 to check existence, 2 to ensure that it matches the
		// provided hostname.
		if (_verify_common_name)
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
		}
		else if (_check_existence)
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 1L);
		}
		else
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
		}

		curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PATCH");

		// for each request header.
		for (const auto& header : requestHeaders)
		{
			// create header name and value.
			std::string headerName(header.first);
			std::string headerValue(header.second);
			std::string header_v = headerName + headerValue;

			// add the header to the header list
			headers = curl_slist_append(headers, header_v.c_str());
		}

		// add the headers
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

		// make the request.
		res = curl_easy_perform(curl);
		if (res != CURLE_OK)
		{
			result = false;
		}
		else
		{
			result = true;
		}

		// clean up
		curl_slist_free_all(headers);
		curl_easy_cleanup(curl);

		// assign result.
		*responseBody = readBuffer;
		*responseHeaders = readHeaders;
	}
	else
	{
		result = false;
	}

	// return
	return result;
}

/// <summary>
/// make patch request
/// </summary>
/// <param name="url">the URL</param>
/// <param name="requestBody">The request body</param>
/// <param name="requestContentType">The request content type</param>
/// <param name="responseBody">The response body</param>
/// <param name="responseHeaders">The response headers</param>
/// <returns>true if success: else false</returns>
bool CurlClient::Patch(const std::string& url, const std::string& requestBody, const std::string& requestContentType,
	std::string* responseBody, std::string* responseHeaders) const
{
	bool result = false;
	CURL* curl;
	CURLcode res;
	std::string readBuffer;
	std::string readHeaders;

	// the url
	auto const& url_request = url;
	struct curl_slist* headers = NULL;

	auto& body_request = requestBody;
	std::string body_content_type = "Content-Type: " + requestContentType;

	curl = curl_easy_init();
	if (curl) {

		// add curl options
		curl_easy_setopt(curl, CURLOPT_URL, url_request.c_str());
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
		curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, WriteHeaderCallback);
		curl_easy_setopt(curl, CURLOPT_WRITEHEADER, &readHeaders);
		curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, (long)CURL_HTTP_VERSION_2TLS);

		// 1L to verify 0L to not verify.
		// Set if we should verify the peer in ssl handshake, set 1 to verify.
		if (_verify_peer)
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
		}
		else
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
		}

		// 1L to verify 0L to not verify.
		// Set if we should verify the Common name from the peer certificate in ssl
		// handshake, set 1 to check existence, 2 to ensure that it matches the
		// provided hostname.
		if (_verify_common_name)
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
		}
		else if (_check_existence)
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 1L);
		}
		else
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
		}

		// post
		std::string post(body_request);
		std::string postLength = std::to_string(post.size());
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body_request.c_str());
		curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PATCH");

		std::string contentTypeNme("Content-Type: ");
		std::string contentTypeArg(requestContentType);
		body_content_type = contentTypeNme + contentTypeArg;

		std::string contentLength = "Content-Length: " + postLength;
		std::string contentType = body_content_type;
		headers = curl_slist_append(headers, contentType.c_str());
		headers = curl_slist_append(headers, contentLength.c_str());
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

		// make the request.
		res = curl_easy_perform(curl);
		if (res != CURLE_OK)
		{
			result = false;
		}
		else
		{
			result = true;
		}

		// clean up
		curl_slist_free_all(headers);
		curl_easy_cleanup(curl);

		// assign result.
		*responseBody = readBuffer;
		*responseHeaders = readHeaders;
	}
	else
	{
		result = false;
	}

	// return
	return result;
}

/// <summary>
/// make patch request
/// </summary>
/// <param name="url">the URL</param>
/// <param name="requestBody">The request body</param>
/// <param name="requestContentType">The request content type</param>
/// <param name="requestHeaders">the request headers</param>
/// <param name="responseBody">The response body</param>
/// <param name="responseHeaders">The response headers</param>
/// <returns>true if success: else false</returns>
bool CurlClient::Patch(const std::string& url, const std::string& requestBody, const std::string& requestContentType,
	const std::map<std::string, std::string>& requestHeaders, std::string* responseBody, std::string* responseHeaders) const
{
	bool result = false;
	CURL* curl;
	CURLcode res;
	std::string readBuffer;
	std::string readHeaders;

	// the url
	auto const& url_request = url;
	struct curl_slist* headers = NULL;

	auto& body_request = requestBody;
	std::string body_content_type = "Content-Type: " + requestContentType;

	curl = curl_easy_init();
	if (curl) {

		// add curl options
		curl_easy_setopt(curl, CURLOPT_URL, url_request.c_str());
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
		curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, WriteHeaderCallback);
		curl_easy_setopt(curl, CURLOPT_WRITEHEADER, &readHeaders);
		curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, (long)CURL_HTTP_VERSION_2TLS);

		// 1L to verify 0L to not verify.
		// Set if we should verify the peer in ssl handshake, set 1 to verify.
		if (_verify_peer)
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
		}
		else
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
		}

		// 1L to verify 0L to not verify.
		// Set if we should verify the Common name from the peer certificate in ssl
		// handshake, set 1 to check existence, 2 to ensure that it matches the
		// provided hostname.
		if (_verify_common_name)
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
		}
		else if (_check_existence)
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 1L);
		}
		else
		{
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
		}

		// post
		std::string post(body_request);
		std::string postLength = std::to_string(post.size());
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body_request.c_str());
		curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PATCH");

		// for each request header.
		for (const auto& header : requestHeaders)
		{
			// create header name and value.
			std::string headerName(header.first);
			std::string headerValue(header.second);
			std::string header_v = headerName + headerValue;

			// add the header to the header list
			headers = curl_slist_append(headers, header_v.c_str());
		}

		std::string contentTypeNme("Content-Type: ");
		std::string contentTypeArg(requestContentType);
		body_content_type = contentTypeNme + contentTypeArg;

		std::string contentLength = "Content-Length: " + postLength;
		std::string contentType = body_content_type;
		headers = curl_slist_append(headers, contentType.c_str());
		headers = curl_slist_append(headers, contentLength.c_str());
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

		// make the request.
		res = curl_easy_perform(curl);
		if (res != CURLE_OK)
		{
			result = false;
		}
		else
		{
			result = true;
		}

		// clean up
		curl_slist_free_all(headers);
		curl_easy_cleanup(curl);

		// assign result.
		*responseBody = readBuffer;
		*responseHeaders = readHeaders;
	}
	else
	{
		result = false;
	}

	// return
	return result;
}