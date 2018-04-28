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

std::vector< std::string > && split( const std::string &text, char sep ) {
    std::vector< std::string > tokens;
    std::size_t start = 0, end = 0;
    while(( end = text.find( sep, start )) != std::string::npos ) {
        auto token = text.substr( start, end - start );
        tokens.emplace_back( trim( token ));
        start = end + 1;
    }
    tokens.push_back( text.substr( start ));
    return std::move( tokens );
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

std::string && getDigest( const std::vector< std::string > &vals ) {
    using CryptoPP::Weak::MD5;
    MD5 digester;
    std::stringstream out;
    byte buffer[ MD5::DIGESTSIZE ];
    for( std::size_t i = 0; i < vals.size(); ++ i ) {
        const auto &val = vals[ i ];
        digester.Update( reinterpret_cast< const byte* >( val.c_str() ),
                        val.size() );
        if( i < vals.size() - 1 ) {
            digester.Update( reinterpret_cast< const byte* >( ":" ), 1 );
        }
    }
    for( int i = 0; i < MD5::DIGESTSIZE; ++i ) {
        out << std::hex << static_cast< uint16_t >( buffer[i] );
    }
    return std::move( out.str() );
}

void printHeaders( httplib::Response &res ) {
    for( auto it = std::begin( res.headers );
         it != std::end( res.headers );
         it ++ ) {
        std::cout << it->first << " == " << it->second << std::endl;
    }
}

std::string && removeQuotes( const std::string &in ) {
    if( in.size() > 2 ) {
        auto first = std::begin( in );
        auto last = std::end( in ) - 1;
        if( *first == '"' ) {
            first ++;
        }
        if( *last == '"' ) {
            last ++;
        }
        return std::move( std::string{ first, last });
    }
    return std::move( std::string{} );
}

void printVector( const std::vector< std::string > &vec ) {
    std::cout << " -- ";
    for( const auto &s : vec ) {
        std::cout << "[" << s << "] ";
    }
    std::cout << std::endl;
}

std::map< std::string, std::string > && authHeaderToMap( const std::string h ) {
    std::map< std::string, std::string > map;
    auto compsOne = split( h, ',' );
    for( const auto &c : compsOne ) {
        auto compsTwo = split( c,  '=' );
        if( compsTwo.size() == 2 ) {
            map[ compsTwo[ 0 ]] = removeQuotes( compsTwo[ 1 ]);
        }
    }
    return  std::move( map );
}

class HttpBinRequester {
public:
    HttpBinRequester(const std::string &userName, const std::string &password)
        : m_userName{ userName }
        , m_password{ password }
        , m_valid{ false }
        , m_client{ "httpbin.org", 443 }
    {
        auto res = m_client.get( URI.c_str() );
        if( res != nullptr ) {
            std::cout << "Status: " << res->status<< std::endl;
            std::cout << res->body << std::endl;
//            printHeaders( *res );
            if( res->status == 401 ) {
                parseAuthInfo( *res );
                m_valid = true;
            }
        }
    }

    bool post( const std::string &url, const std::string &content ) {
        auto result = false;
        httplib::Headers headers;
        const auto res = m_client.post(
                    url.c_str(),
                    headers,
                    content,
                    "text/plain" );
        if( res != nullptr )  {
            std::cout << "Result Status: " << res->status << std::endl;
            std::cout << "Result Body: " << res->body << std::endl;
            result = ( res->status - 200 ) < 200;

        } else {
            std::cout << "Failed to get valid response" << std::endl;
        }

        return  false;
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
                auto hash2 = getDigest({ "POST", URI  });
                m_hash = getDigest({ hash1, m_nonce, hash2 });
            }
        }
    }

    static const std::string URI;

private:

    std::string m_userName;

    std::string m_password;

    bool m_valid;

    httplib::SSLClient m_client;

    std::string m_realm;

    std::string m_nonce;

    std::string m_opaque;

    std::string m_hash;
};
const std::string HttpBinRequester::URI =
        "/digest-auth/auth/user/password/md5/never";

std::string readWiki() {
    httplib::SSLClient cli{"en.wikipedia.org", 443};
//     httplib::Client cli{"en.wikipedia.org", 80};

    auto res = cli.get("/wiki/JUCE", nullptr);
    if (res && res->status == 200) {
        if(res) {
            std::cout << "Status Code: "
                      << res->status << std::endl
                      << res->body;
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
        auto r = req.post( HttpBinRequester::URI, wiki );
        std::cout << ( r ? "Done" : "Failed" ) << std::endl;
    } else {
        std::cout << "Wiki retrieval failed" << std::endl;
    }

}


