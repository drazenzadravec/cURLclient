#pragma once

#include "pch.h"
#include "globalcurl.h"

namespace Nequeo {
	namespace Net {

		///	<summary>
		///	cURL client.
		///	</summary>
		class CurlClient
		{
		public:
			///	<summary>
			///	cURL client.
			///	</summary>
			CurlClient();

			///	<summary>
			///	cURL client.
			///	</summary>
			virtual ~CurlClient();

			/// <summary>
			/// Verify the peer in ssl handshake, set true to verify, false to bypass.
			/// </summary>
			/// <param name="verifyPeer">true to verify peer: else false.</param>
			void SetVerifyPeer(bool verifyPeer);

			/// <summary>
			/// Verify the Common name from the peer certificate in ssl
			/// handshake, set true to check existence, true to ensure that it matches the
			/// provided hostname.
			/// </summary>
			/// <param name="checkExistence">true to check existence: else false.</param>
			/// <param name="verifyCommonName">true to verify common name: else false.</param>
			void SetVerifyCommonName(bool checkExistence, bool verifyCommonName);

			/// <summary>
			/// make options request.
			/// </summary>
			/// <param name="url">the URL</param>
			/// <param name="responseBody">The response body</param>
			/// <param name="responseHeaders">The response headers</param>
			/// <returns>true if success: else false</returns>
			bool Options(const std::string& url, std::string* responseBody, std::string* responseHeaders) const;

			/// <summary>
			/// make options request.
			/// </summary>
			/// <param name="url">the URL</param>
			/// <param name="requestHeaders">the request headers</param>
			/// <param name="responseBody">The response body</param>
			/// <param name="responseHeaders">The response headers</param>
			/// <returns>true if success: else false</returns>
			/// <example>
			///		request headers:
			///			map:	'Authorization: ', 'Bearer: token'
			/// </example>
			bool Options(const std::string& url, const std::map<std::string, std::string>& requestHeaders,
				std::string* responseBody, std::string* responseHeaders) const;

			/// <summary>
			/// make head request.
			/// </summary>
			/// <param name="url">the URL</param>
			/// <param name="responseHeaders">The response headers</param>
			/// <returns>true if success: else false</returns>
			bool Head(const std::string& url, std::string* responseHeaders) const;

			/// <summary>
			/// make head request.
			/// </summary>
			/// <param name="url">the URL</param>
			/// <param name="requestHeaders">the request headers</param>
			/// <param name="responseHeaders">The response headers</param>
			/// <returns>true if success: else false</returns>
			/// <example>
			///		request headers:
			///			map:	'Authorization: ', 'Bearer: token'
			/// </example>
			bool Head(const std::string& url, const std::map<std::string, std::string>& requestHeaders, std::string* responseHeaders) const;

			/// <summary>
			/// make get request.
			/// </summary>
			/// <param name="url">the URL</param>
			/// <param name="responseBody">The response body</param>
			/// <param name="responseHeaders">The response headers</param>
			/// <returns>true if success: else false</returns>
			bool Get(const std::string& url, std::string* responseBody, std::string* responseHeaders) const;

			/// <summary>
			/// make get request.
			/// </summary>
			/// <param name="url">the URL</param>
			/// <param name="requestHeaders">the request headers</param>
			/// <param name="responseBody">The response body</param>
			/// <param name="responseHeaders">The response headers</param>
			/// <returns>true if success: else false</returns>
			/// <example>
			///		request headers:
			///			map:	'Authorization: ', 'Bearer: token'
			/// </example>
			bool Get(const std::string& url, const std::map<std::string, std::string>& requestHeaders, std::string* responseBody, std::string* responseHeaders) const;

			/// <summary>
			/// make post request
			/// </summary>
			/// <param name="url">the URL</param>
			/// <param name="requestBody">The request body</param>
			/// <param name="requestContentType">The request content type</param>
			/// <param name="responseBody">The response body</param>
			/// <param name="responseHeaders">The response headers</param>
			/// <returns>true if success: else false</returns>
			bool Post(const std::string& url, const std::string& requestBody, const std::string& requestContentType,
				std::string* responseBody, std::string* responseHeaders) const;

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
			/// <example>
			///		request headers:
			///			map:	'Authorization: ', 'Bearer: token'
			/// </example>
			bool Post(const std::string& url, const std::string& requestBody, const std::string& requestContentType,
				const std::map<std::string, std::string>& requestHeaders, std::string* responseBody, std::string* responseHeaders) const;

			/// <summary>
			/// make put request.
			/// </summary>
			/// <param name="url">the URL</param>
			/// <param name="responseBody">The response body</param>
			/// <param name="responseHeaders">The response headers</param>
			/// <returns>true if success: else false</returns>
			bool Put(const std::string& url, std::string* responseBody, std::string* responseHeaders) const;

			/// <summary>
			/// make put request.
			/// </summary>
			/// <param name="url">the URL</param>
			/// <param name="requestHeaders">the request headers</param>
			/// <param name="responseBody">The response body</param>
			/// <param name="responseHeaders">The response headers</param>
			/// <returns>true if success: else false</returns>
			/// <example>
			///		request headers:
			///			map:	'Authorization: ', 'Bearer: token'
			/// </example>
			bool Put(const std::string& url, const std::map<std::string, std::string>& requestHeaders, std::string* responseBody, std::string* responseHeaders) const;

			/// <summary>
			/// make put request
			/// </summary>
			/// <param name="url">the URL</param>
			/// <param name="requestBody">The request body</param>
			/// <param name="requestContentType">The request content type</param>
			/// <param name="responseBody">The response body</param>
			/// <param name="responseHeaders">The response headers</param>
			/// <returns>true if success: else false</returns>
			bool Put(const std::string& url, const std::string& requestBody, const std::string& requestContentType,
				std::string* responseBody, std::string* responseHeaders) const;

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
			/// <example>
			///		request headers:
			///			map:	'Authorization: ', 'Bearer: token'
			/// </example>
			bool Put(const std::string& url, const std::string& requestBody, const std::string& requestContentType,
				const std::map<std::string, std::string>& requestHeaders, std::string* responseBody, std::string* responseHeaders) const;

			/// <summary>
			/// make delete request.
			/// </summary>
			/// <param name="url">the URL</param>
			/// <param name="responseBody">The response body</param>
			/// <param name="responseHeaders">The response headers</param>
			/// <returns>true if success: else false</returns>
			bool Delete(const std::string& url, std::string* responseBody, std::string* responseHeaders) const;

			/// <summary>
			/// make delete request.
			/// </summary>
			/// <param name="url">the URL</param>
			/// <param name="requestHeaders">the request headers</param>
			/// <param name="responseBody">The response body</param>
			/// <param name="responseHeaders">The response headers</param>
			/// <returns>true if success: else false</returns>
			/// <example>
			///		request headers:
			///			map:	'Authorization: ', 'Bearer: token'
			/// </example>
			bool Delete(const std::string& url, const std::map<std::string, std::string>& requestHeaders, std::string* responseBody, std::string* responseHeaders) const;

			/// <summary>
			/// make delete request
			/// </summary>
			/// <param name="url">the URL</param>
			/// <param name="requestBody">The request body</param>
			/// <param name="requestContentType">The request content type</param>
			/// <param name="responseBody">The response body</param>
			/// <param name="responseHeaders">The response headers</param>
			/// <returns>true if success: else false</returns>
			bool Delete(const std::string& url, const std::string& requestBody, const std::string& requestContentType,
				std::string* responseBody, std::string* responseHeaders) const;

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
			/// <example>
			///		request headers:
			///			map:	'Authorization: ', 'Bearer: token'
			/// </example>
			bool Delete(const std::string& url, const std::string& requestBody, const std::string& requestContentType,
				const std::map<std::string, std::string>& requestHeaders, std::string* responseBody, std::string* responseHeaders) const;

			/// <summary>
			/// make patch request.
			/// </summary>
			/// <param name="url">the URL</param>
			/// <param name="responseBody">The response body</param>
			/// <param name="responseHeaders">The response headers</param>
			/// <returns>true if success: else false</returns>
			bool Patch(const std::string& url, std::string* responseBody, std::string* responseHeaders) const;

			/// <summary>
			/// make patch request.
			/// </summary>
			/// <param name="url">the URL</param>
			/// <param name="requestHeaders">the request headers</param>
			/// <param name="responseBody">The response body</param>
			/// <param name="responseHeaders">The response headers</param>
			/// <returns>true if success: else false</returns>
			/// <example>
			///		request headers:
			///			map:	'Authorization: ', 'Bearer: token'
			/// </example>
			bool Patch(const std::string& url, const std::map<std::string, std::string>& requestHeaders, std::string* responseBody, std::string* responseHeaders) const;

			/// <summary>
			/// make patch request
			/// </summary>
			/// <param name="url">the URL</param>
			/// <param name="requestBody">The request body</param>
			/// <param name="requestContentType">The request content type</param>
			/// <param name="responseBody">The response body</param>
			/// <param name="responseHeaders">The response headers</param>
			/// <returns>true if success: else false</returns>
			bool Patch(const std::string& url, const std::string& requestBody, const std::string& requestContentType,
				std::string* responseBody, std::string* responseHeaders) const;

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
			/// <example>
			///		request headers:
			///			map:	'Authorization: ', 'Bearer: token'
			/// </example>
			bool Patch(const std::string& url, const std::string& requestBody, const std::string& requestContentType,
				const std::map<std::string, std::string>& requestHeaders, std::string* responseBody, std::string* responseHeaders) const;

		private:
			bool _disposed;
			bool _verify_peer;
			bool _check_existence;
			bool _verify_common_name;
		};
	}
}