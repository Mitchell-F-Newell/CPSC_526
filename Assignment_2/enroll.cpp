#include<iostream>
#include<string>
#include<cstring>
#include<vector>
#include<fstream>
#include <algorithm>
#include<ctime>
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

//Check to make sure username does not already exist in the database
void usernameCheck(std::string userName) {
    std::vector<Database> dbData = getDatabase();
    
    if(dbData.size() > 0){
        for (int i = 0; i < dbData.size(); i++) {
            if(dbData[i].username == userName){
                std::cout << "rejected.\n";
                exit(-1);
            }
        }
    }
}

//Check that the input password is not weak
void passwordCheck(char* password) {
    std::vector<std::string> dictionary;
    std::string word;
    std::ifstream infile("dictionary.txt");
    std::string stringPassword = password;
    std::string stringPasswordCPY = stringPassword;

    while (std::getline(infile, word)) {
        dictionary.push_back(word);
    }
    
    //Check is password is just numbers
    stringPasswordCPY.erase(std::remove_if(std::begin(stringPasswordCPY), std::end(stringPasswordCPY), [](auto ch) { return std::isdigit(ch); }), stringPasswordCPY.end());
    if(stringPasswordCPY ==""){
        std::cout << "rejected.\n";
        exit(-1);
    }


    //Check is password is a dictionary word
    if (std::count(dictionary.begin(), dictionary.end(), stringPassword)){
        std::cout << "rejected.\n";
        exit(-1);
    }

    //Check for [numword] case
    stringPasswordCPY = stringPassword;
    for(int i = 0; i <  stringPasswordCPY.length(); i++) {
        if(isdigit(stringPasswordCPY[i])){
            stringPasswordCPY.erase(i, 1);
            i = -1;
        } else {
            break;
        }
    }
    if (std::count(dictionary.begin(), dictionary.end(), stringPasswordCPY)){
        std::cout << "rejected.\n";
        exit(-1);
    }

    //Check for [wordnum] case
    stringPasswordCPY = stringPassword;
    for(int i = stringPassword.length()-1; i >= 0; i--) {
        if(isdigit(stringPasswordCPY[i])){
            stringPasswordCPY.erase(i, 1);
        } else {
            break;
        }
    }
    if (std::count(dictionary.begin(), dictionary.end(), stringPasswordCPY)){
        std::cout << "rejected.\n";
        exit(-1);
    }
}


//Add a user to the system database
void addUser(char* username, char* password) {
    int saltValue = std::time(0);
    uint8_t salt[SALTLEN];
    memset(salt, saltValue, SALTLEN);

    uint8_t passwordHash[HASHLEN];

    hashPassword(passwordHash, salt, password);

    FILE *outputFile;
    outputFile = fopen("databaseData.txt", "a");
    fprintf(outputFile, "%s ", username);
    for(int i=0; i<HASHLEN; ++i) fprintf(outputFile, "%02x", passwordHash[i]);
    fprintf(outputFile, " %d\n", saltValue);
    fclose(outputFile);
}

int main(int argc, char *argv[])
{
    if(argc < 3) {
        std::cout << "rejected.\n";
        exit(-1);
    }

    char* username = argv[1];
    char* password = argv[2];

    usernameCheck(username);
    passwordCheck(password);
    addUser(username, password);

    std::cout << "Accepted\n";
    exit(0);
}