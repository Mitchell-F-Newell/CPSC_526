#include<iostream>
#include<string>
#include<cstring>
#include<vector>
#include<fstream>
#include "argon2/include/argon2.h"

#define HASHLEN 32
#define SALTLEN 16

//Class for the database objects
class Database {
    public: 
        //Instance variables
        std::string username;
        std::string password;
        int saltValue;
};

//Hash the user password using Argon2
uint8_t hashPassword(uint8_t* hash1, uint8_t* salt, char* password) {
    
    uint8_t *pwd = (uint8_t *)strdup(password);
    uint32_t pwdlen = strlen((char *)password);

    uint32_t t_cost = 2;            // 1-pass computation
    uint32_t m_cost = (1<<16);      // 64 mebibytes memory usage
    uint32_t parallelism = 1;       // number of threads and lanes
    // high-level API
    argon2i_hash_raw(t_cost, m_cost, parallelism, pwd, pwdlen, salt, SALTLEN, hash1, HASHLEN);
}

//Read database into vector of database objects
std::vector<Database> getDatabase(){

    std::vector<Database> dbVector;
    Database dbObj;

    std::ifstream infile("databaseData.txt");

    std::string username;
    std::string password;
    int saltValue;
    
    while (infile >> username >> password >> saltValue)
    {   
        dbObj.username = username;
        dbObj.password = password;
        dbObj.saltValue = saltValue;
        dbVector.push_back(dbObj);        
    }
    infile.close();
    return dbVector;
}

//Match the input password with the hashed password and authenticate the user.
void authenticate(char* username, char* password) {
    
    std::vector<Database> dbData = getDatabase();
    
    if(dbData.size() > 0){
        for (int i = 0; i < dbData.size(); i++) {
            if(dbData[i].username == username){
                int saltValue = dbData[i].saltValue;

                uint8_t salt[SALTLEN];
                memset(salt, saltValue, SALTLEN);
                uint8_t passwordHash[HASHLEN];

                hashPassword(passwordHash, salt, password);

                std::cout<<std::endl;
                std::cout<<std::endl;
                char hash[2 * HASHLEN + 1];
                for(int i = 0; i < HASHLEN; i++) {
                    snprintf(hash + 2 * i, 2 * HASHLEN - 2 * i + 1, "%02x", passwordHash[i]);
                }
                hash[2 * HASHLEN] = '\0';
                if(std::strcmp(hash, dbData[i].password.c_str()) == 0){
                    std::cout<<"Access granted\n";
                    exit(0);
                }
            }
        }
    }
    std::cout<<"Access denied\n";
    exit(-1);
}


int main(int argc, char *argv[])
{
    if(argc < 3) {
        std::cout << "Access denied\n";
        exit(-1);
    }

    char* username = argv[1];
    char* password = argv[2];

    authenticate(username, password);
}