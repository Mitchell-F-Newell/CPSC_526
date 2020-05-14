#include <iostream>
#include <string>

using namespace std;

string some_hash(const string& input) {
    string retval = "\x0f\xff\x00";
        for (size_t i = 0; i < input.length(); ++i) {
            retval[0] ^= input[i];
            retval[1] &= input[i];
            retval[2] |= input[i];
        }
    return retval;
}

string second_preimage_generator(const string& input){
    char inputCharacter0 = input[0];
    string secondPreimage = input + inputCharacter0 + inputCharacter0;

    return secondPreimage;
}

int main ()
{
  string input;
  cout << "Please enter an arbitrary string: ";
  cin >> input;
  cout << "The string you entered is: " << input << endl;

  string hash = some_hash(input);
  cout << "The hash for the input string is: " << endl;
  for(int i = 0; i <= hash.length(); i++){
    cout << hash[i] << endl;
  }
  
  string secondPreimage = second_preimage_generator(input);
  cout << "\nThe calculated second preimage is: " << secondPreimage << endl;
  
  string secondPreimageHash = some_hash(secondPreimage);
  cout << "The hash for the generated second preimage is: " << endl;
  for (int i = 0; i <= secondPreimageHash.length(); i++){
    cout << secondPreimageHash[i] << endl;
  }

  if (secondPreimageHash == hash) {
      cout << "\nA collision has been detected." << endl << "Generated second preimage was successful." << endl;
  } else {
      cout << "No collision has been detected." << endl << "Generated second preimage was not successful." << endl;
  } 
}