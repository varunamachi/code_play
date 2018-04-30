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

template< typename T >
byte * tb( T *in ) {
    return reinterpret_cast< byte * >(
                const_cast< typename std::remove_cv< T >::type * >( in ));
}

enum class HttpMethod {
    GET,
    POST,
};

struct ByteArray {
    explicit ByteArray( byte *data, std::size_t size )
        : m_data{ data }
        , m_size{ size }
    {

    }

    byte *m_data;

    std::size_t m_size;

    std::size_t size() const {
        return m_size;
    }

    byte * data() const {
        return m_data;
    }

    friend std::ostream & operator << ( std::ostream &stream,
                                        const ByteArray &arr ) {
        for( std::size_t i = 0; i < arr.m_size; ++i ) {
            stream << std::hex << static_cast< uint16_t >( arr.m_data[ i ] );
        }
        return stream;
    }
};

template< std::size_t SIZE >
std::ostream &operator << ( std::ostream &stream,
                            const std::array< byte, SIZE > &arr ) {
    for( std::size_t i = 0; i < arr.size(); ++i ) {
        stream << std::hex << static_cast< uint16_t >( arr[ i ] );
    }
    return stream;
}

inline ByteArray toBA( const std::string &s ) {
    return ByteArray{ tb( s.c_str() ), s.size() };
}

template< std::size_t SIZE >
inline ByteArray toBA( const std::array< byte, SIZE > &s ) {
    return ByteArray{ tb( s.data() ), s.size() };
}

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

std::array< byte, 16 > getDigest( const std::vector< ByteArray > &vals ) {
    using CryptoPP::Weak::MD5;
    MD5 digester;
    std::array< byte, MD5::DIGESTSIZE > buffer;

    std::size_t fullSize = 0;
    for( auto &bs : vals ) {
        fullSize += bs.size();
    }
    fullSize += vals.size() - 1; // for ':' chars
    auto inBuffer = new byte[ fullSize ];
    auto index = 0;
    for( std::size_t i = 0;  i < vals.size(); ++ i ) {
        auto &s = vals[ i ];
        std::memcpy( &inBuffer[ index ], s.data(), s.size() );
        index += s.size();
        if( i < vals.size() - 1 ) {
            inBuffer[ index ++ ] = ':';
        }
    }
    digester.CalculateDigest( buffer.data(), inBuffer, fullSize );
    delete[] inBuffer;
    return buffer;
}

void printHeaders( httplib::Response &res ) {
    for( auto it = std::begin( res.headers );
         it != std::end( res.headers );
         it ++ ) {
        std::cout << it->first << " == " << it->second << std::endl;
    }
}

bool hexToBytes( const std::string &asciiHex, byte *bytes )
{
    std::size_t numBytes = asciiHex.size() / 2;
    auto result = false;
    if( numBytes ) {
        std::memset( bytes, 0, numBytes );
        for( std::size_t i = 0, index = 0;
             i < asciiHex.size();
             i += 2, ++ index ) {
            for( std::size_t j = i; j < ( i + 2 ); ++ j ) {
                std::uint8_t nibble = 0;
                if( asciiHex[ j ] >= '0' && asciiHex[ j ] <= '9' ) {
                    nibble = ( asciiHex[ j ] - 0x30 ) & 0x0F;
                }
                else if( asciiHex[ j ] >= 'A' && asciiHex[ j ] <= 'F' ) {
                    nibble = ( asciiHex[ j ] - 0x37 ) & 0xFF;
                }
                else if( asciiHex[ j ] >= 'a' && asciiHex[ j ] <= 'f' ) {
                    nibble = ( asciiHex[ j ] - 0x57 ) & 0x0F;
                }
                else {
                    std::cout << "ToBytes - invalid character found \n";
                }
                std::uint8_t shift = static_cast<
                        std::uint8_t >((( i + 1 ) - j ) * 4 );
                bytes[ index ] |= nibble << shift;
            }
        }
        result = true;
    }
    return result;
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
        , m_nonceCount{ 1 }
        , m_cnonce{ "fg4ghe" }
        , m_valid{ false }
        , m_client{ "eu.httpbin.org", 443 }

    {
        httplib::Headers headers;
        headers.insert({ "Set-Cookie", "fake=fake_value" });
        auto res = m_client.get( URI.c_str() );
        if( res != nullptr ) {
            std::cout << "Result Status: " << res->status<< std::endl;
            std::cout << res->body << std::endl;
            if( res->status == 401 ) {
//                printHeaders( *res );
//                std::cout << " - - - - - - - - - - -" << std::endl;
                parseAuthInfo( *res );
                m_valid = true;
            }
        }
    }

    void addAuthHeaders( const std::array< byte, 16 > &response,
                         httplib::Headers &headersOut ) {
        std::stringstream authHdrStream;
        authHdrStream << "Digest username=\"" << m_userName << "\", realm=\""
                      << m_realm << "\", nonce=\""
                      << m_nonce << "\", uri=\""
                      << URI << "\", qop=\"auth\", "
                      << "nc=" << m_nonceCount << ", "
                      << "cnonce=\"" << m_cnonce << "\", "
                      << "response=\""
                      << response << "\", opaque=\""
                      << m_opaque << "\"";
        auto val = authHdrStream.str();
        std::cout << "\n ======== " << std::endl;
        std::cout << "Auth Header: " << val << std::endl;
        std::cout << " ======== \n" << std::endl;
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
            addAuthHeaders( m_getHash, headers );
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
            std::cout << "Result Status: "
                      << std::dec
                      << res->status
                      << std::endl;
            std::cout << "Result Body: "
                      << res->body
                      << std::endl;
            result = ( res->status - 200 ) < 200;
            printHeaders( *res );

        } else {
            std::cout << "Failed to get valid response" << std::endl;
        }
        return  result;
    }

    bool parseAuthInfo( httplib::Response &res ) {
        // Digest
        // realm="me@kennethreitz.com",
        // nonce="9a046325ca9ef842370026fc8ab7ad0a",
        // qop="auth",
        // opaque="0c0b7117690cf27a1cb3c3c797dbcfbc",
        // algorithm=MD5,
        // stale=FALSE
        auto result = false;
        auto it = res.headers.find( "Www-Authenticate" );
        if( it != std::end( res.headers )) {
            auto fh = it->second;
            if( startsWith( fh, "Digest")) {
                auto h = fh.substr( 7 );
                auto headerMap = authHeaderToMap( h );
                m_realm = headerMap[ "realm" ];
                if( hexToBytes( headerMap[ "nonce" ], m_nonce.data() ) &&
                        hexToBytes( headerMap[ "opaque" ], m_opaque.data() )) {
                    auto hash1 = getDigest({ toBA( m_userName ),
                                             toBA( m_realm ),
                                             toBA( m_password )});
                    std::cout << "HASH1: " << hash1 << std::endl;

                    auto pHash = getDigest({ toBA( std::string{ "POST" }),
                                             toBA( URI )});
                    std::cout << "P HASH: " << pHash << std::endl;

                    auto gHash = getDigest({ toBA( std::string{ "GET" }),
                                             toBA( URI )});
                    std::cout << "G HASH: " << gHash << std::endl;

                    m_postHash = getDigest({ toBA( hash1 ),
                                             toBA( m_nonce ),
                                             ByteArray{ &m_nonceCount, 1},
                                             toBA( m_cnonce ),
                                             toBA( "auth" ),
                                             toBA( pHash )});
                    std::cout << "POST R: " << m_postHash << std::endl;


                    std::cout << hash1
                              << ":"
                              << m_nonce
                              << ":"
                              << 1 << ":"
                              << m_cnonce << ":"
                              << "auth:"
                              << gHash
                              << "\n";

                    m_getHash  = getDigest({ toBA( hash1 ),
                                             toBA( m_nonce ),
                                             ByteArray{ &m_nonceCount, 1},
                                             toBA( m_cnonce ),
                                             toBA( "auth" ),
                                             toBA( gHash )
                                           });
                    std::cout << "GET R: " << m_getHash << std::endl;
                    result = true;
                }
                else {
                    std::cout << "Invalid auth info given by server"
                              << std::endl;
                }
            }
        }
        return result;
    }

    static const std::string URI;

private:

    std::string m_userName;

    std::string m_password;

    byte  m_nonceCount;

    std::string m_cnonce;

    bool m_valid;

    httplib::SSLClient m_client;

    std::string m_realm;

    std::array< byte, 16 > m_nonce;

    std::array< byte, 16 > m_opaque;

    std::array< byte, 16 > m_postHash;

    std::array< byte, 16 > m_getHash;
};

const std::string HttpBinRequester::URI =
        "/digest-auth/auth/user/passwd/md5/never";

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
    HttpBinRequester req{ "user", "passwd" };
//    auto wiki = readWiki();
    auto wiki = std::string{ "Wiki sample" };
    if( wiki.size() > 0 ) {
        auto r = req.request( HttpMethod::GET, HttpBinRequester::URI, wiki );
        std::cout << ( r ? "Done" : "Failed" ) << std::endl;
    } else {
        std::cout << "Wiki retrieval failed" << std::endl;
    }

}


