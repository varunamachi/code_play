#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#define CPPHTTPLIB_OPENSSL_SUPPORT

#include <iostream>
#include <vector>
#include <sstream>
#include <string>
#include <algorithm>
#include <ctype.h>

#include <crypto++/md5.h>


#include "httplib.h"

enum class HttpMethod {
    GET,
    POST,
};

inline std::string trim( const std::string &str )
{
   auto front = std::find_if_not(
               str.begin(),
               str.end(),
               []( int c ) {
       return std::isspace(c);
   });
   auto back = std::find_if_not(
               str.rbegin(),
               str.rend(),
               [](int c) {
       return std::isspace(c);
   }).base();
   return back <= front ? std::string{} : std::string{ front, back };
}

std::vector< std::string > split( const std::string &text, char sep ) {
    std::vector< std::string > tokens;
    std::size_t start = 0, end = 0;
    while(( end = text.find( sep, start )) != std::string::npos ) {
        auto token = text.substr( start, end - start );
        tokens.emplace_back( trim( token ));
        start = end + 1;
    }
    tokens.push_back( text.substr( start ));
    return tokens;
}

bool startsWith( const std::string &main, const std::string &check ) {
    auto result = !check.empty();
    for( std::string::size_type i = 0; i < check.size(); ++ i ) {
        if( check[ i ] != main[ i ]) {
            result = false;
        }
    }
    return result;
}

///@todo - use vector of byte buffer instead of strings
std::string getDigest( const std::vector< std::basic_string< byte >> &vals ) {
    using CryptoPP::Weak::MD5;
    MD5 digester;
    std::stringstream out;
    byte buffer[ MD5::DIGESTSIZE ];

    auto fullSize = 0;
    for( auto &bs : vals ) {
        fullSize += bs.size();
    }
    fullSize += vals.size() - 1; // for ':' chars
    auto inBuffer = new byte[ fullSize ];
    delete[] inBuffer;
    for( int i = 0; i < MD5::DIGESTSIZE; ++i ) {
        out << std::hex << static_cast< uint16_t >( buffer[i] );
    }
    auto digest = out.str();
    return digest;
}

std::string getDigest( const std::vector< std::string > &vals ) {
    using CryptoPP::Weak::MD5;
    MD5 digester;
    std::stringstream out;
    std::stringstream stream;
    byte buffer[ MD5::DIGESTSIZE ];

    for( std::size_t i = 0; i < vals.size(); ++ i ) {
        const auto &val = vals[ i ];
        stream << val;
        if( i < vals.size() - 1 ) {
            stream << ":";
        }
    }
    auto hval = stream.str();
    digester.CalculateDigest( buffer,
                              reinterpret_cast< const byte* >( hval.c_str() ),
                              hval.size() );
    for( int i = 0; i < MD5::DIGESTSIZE; ++i ) {
        out << std::hex << static_cast< uint16_t >( buffer[i] );
    }
    auto digest = out.str();
    std::cout << "CalcDigest: " << hval << " => "  << digest << std::endl;
    return digest;
}

void printHeaders( httplib::Response &res ) {
    for( auto it = std::begin( res.headers );
         it != std::end( res.headers );
         it ++ ) {
        std::cout << it->first << " == " << it->second << std::endl;
    }
}

std::string removeQuotes( const std::string &in ) {
    if( in.size() > 2 ) {
        auto first = std::begin( in );
        auto last = std::end( in );
        if( *first == '"' ) {
            first ++;
        }
        if( *( last - 1 ) == '"' ) {
            last --;
        }
        return std::string{ first, last };
    }
    return std::string{};
}

void printVector( const std::vector< std::string > &vec ) {
    std::cout << " -- ";
    for( const auto &s : vec ) {
        std::cout << "[" << s << "] ";
    }
    std::cout << std::endl;
}

std::map< std::string, std::string > authHeaderToMap( const std::string h ) {
    std::map< std::string, std::string > map;
    auto compsOne = split( h, ',' );
    for( const auto &c :  compsOne ) {
        auto compsTwo = split( c,  '=' );
        if( compsTwo.size() == 2 ) {
            map[ compsTwo[ 0 ]] = removeQuotes( compsTwo[ 1 ]);
        }
    }
    return map;
}

class HttpBinRequester {
public:
    HttpBinRequester(const std::string &userName, const std::string &password)
        : m_userName{ userName }
        , m_password{ password }
        , m_nonceCount{ "1" }
        , m_cnonce{ "fg4ghe" }
        , m_valid{ false }
        , m_client{ "httpbin.org", 443 }

    {
        httplib::Headers headers;
        headers.insert({ "Set-Cookie", "fake=fake_value" });
        auto res = m_client.get( URI.c_str() );
        if( res != nullptr ) {
            std::cout << "Result Status: " << res->status<< std::endl;
            std::cout << res->body << std::endl;
            if( res->status == 401 ) {
                printHeaders( *res );
                std::cout << " - - - - - - - - - - -" << std::endl;
                parseAuthInfo( *res );
                m_valid = true;
            }
        }
    }

    void addAuthHeaders( const std::string &response,
                         httplib::Headers &headersOut ) {
        std::stringstream authHdrStream;
        authHdrStream << "Digest username=\"" << m_userName << "\", realm=\""
                      << m_realm << "\", nonce=\""
                      << m_nonce << "\", uri=\""
                      << URI << "\", qop=auth, "
                      << "nc=" << m_nonceCount << ", "
                      << "cnonce=\"" << m_cnonce << "\", "
                      << "response=\""
                      << response << "\", opaque=\""
                      << m_opaque << "\"";
        auto val = authHdrStream.str();
        std::cout << "Auth Header: " << val << std::endl;
        headersOut.insert({ "Authorization",  val });
        headersOut.insert({ "Set-Cookie", "fake=fake_value" });
    }

    bool request(  HttpMethod method,
                   const std::string &url,
                   const std::string &content ) {
        auto result = false;
        httplib::Headers headers;
        std::shared_ptr< httplib::Response > res;
        switch ( method ) {
        case HttpMethod::GET: {
            addAuthHeaders( m_postHash, headers );
            res = m_client.get( url.c_str(), headers );
            break;
        }
        case HttpMethod::POST: {
            addAuthHeaders( m_postHash, headers );
            res = m_client.post( url.c_str(), headers, content, "text/plain" );
            break;
        }

        }
        if( res != nullptr )  {
            std::cout << "Result Status: " << res->status << std::endl;
            std::cout << "Result Body: " << res->body << std::endl;
            result = ( res->status - 200 ) < 200;
            printHeaders( *res );

        } else {
            std::cout << "Failed to get valid response" << std::endl;
        }
        return  result;
    }

    void parseAuthInfo( httplib::Response &res ) {
        // Digest
        // realm="me@kennethreitz.com",
        // nonce="9a046325ca9ef842370026fc8ab7ad0a",
        // qop="auth",
        // opaque="0c0b7117690cf27a1cb3c3c797dbcfbc",
        // algorithm=MD5,
        // stale=FALSE
        auto it = res.headers.find( "Www-Authenticate" );
        if( it != std::end( res.headers )) {
            auto fh = it->second;
            if( startsWith( fh, "Digest")) {
                auto h = fh.substr( 7 );
                auto headerMap = authHeaderToMap( h );
                m_realm = headerMap[ "realm" ];
                m_nonce = headerMap[ "nonce" ];
                m_opaque = headerMap[ "opaque" ];
                auto hash1 = getDigest({ m_userName,  m_realm, m_password });
                auto pHash = getDigest({ "POST", URI  });
                auto gHash = getDigest({ "GET", URI  });
                m_postHash = getDigest({ hash1,
                                         m_nonceCount,
                                         m_cnonce,
                                         m_nonce,
                                         pHash });
                m_getHash  = getDigest({ hash1, m_nonce, gHash });
            }
        }
    }

    static const std::string URI;

private:

    std::string m_userName;

    std::string m_password;

    std::string m_nonceCount;

    std::string m_cnonce;

    bool m_valid;

    httplib::SSLClient m_client;

    std::string m_realm;

    std::string m_nonce;

    std::string m_opaque;

    std::string m_postHash;

    std::string m_getHash;
};

const std::string HttpBinRequester::URI =
        "/digest-auth/auth/user/password/md5/never";

std::string readWiki() {
    httplib::SSLClient cli{"en.wikipedia.org", 443};
//     httplib::Client cli{"en.wikipedia.org", 80};

    auto res = cli.get("/wiki/JUCE", nullptr);
    if (res && res->status == 200) {
        if(res) {
            std::cout << "Wiki Read - Status Code: "
                      << res->status << std::endl;
        } else {
            std::cout << "Write failed without status code" << std::endl;
        }

    } else if (res != nullptr) {
        std::cout << "Status Code: " << res->status << std::endl;
    } else {
        std::cout << "Read failed without status code" << std::endl;
    }
    return res->body;
}


int main()
{
    HttpBinRequester req{ "user", "password" };
    auto wiki = readWiki();
    if( wiki.size() > 0 ) {
        auto r = req.request( HttpMethod::GET, HttpBinRequester::URI, wiki );
        std::cout << ( r ? "Done" : "Failed" ) << std::endl;
    } else {
        std::cout << "Wiki retrieval failed" << std::endl;
    }

}


