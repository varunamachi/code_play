#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#define CPPHTTPLIB_OPENSSL_SUPPORT

#include <iostream>
#include <crypto++/md5.h>


#include "httplib.h"

void streamDigest(std::vector< std::string > vals, std::stringstream &out) {
    using CryptoPP::Weak::MD5;
    MD5 digester;
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
}

void printHeaders( httplib::Response &res ) {
    for( auto it = std::begin( res.headers );
         it != std::end( res.headers );
         it ++ ) {
        std::cout << it->first << " == " << it->second << std::endl;
    }
}

class HttpBinRequester {
public:
    HttpBinRequester(std::string userName, std::string password)
        : m_userName{ userName }
        , m_password{ password }
        , m_valid{ false }
        , m_client{ "httpbin.org", 443 }
    {
        auto res = m_client.get( "/digest-auth/auth/user/password/md5/never");
        if( res != nullptr ) {
            std::cout << "Status: " << res->status<< std::endl;
            std::cout << res->body << std::endl;
            printHeaders( *res );
            if( res->status == 401 ) {
                //calculate the hashes
                m_valid = true;
            }
        }
    }

    bool post( std::string /*url*/, std::string /*content*/ ) {

    }


private:
    std::string m_userName;

    std::string m_password;

    bool m_valid;

    httplib::SSLClient m_client;

    std::string m_realm;

    std::string m_nounce;



};

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
        auto r = req.post( "/digest-auth/auth/user/password/md5/never", wiki );
        std::cout << ( r ? "Done" : "Failed" ) << std::endl;
    } else {
        std::cout << "Wiki retrieval failed" << std::endl;
    }

}


