#will allow us to make requests
import requests
import hashlib 
import sys

#for password api url

def request_api_data(query_char):
    
     #our password is going to be sent in hash version for security
    
    url="https://api.pwnedpasswords.com/range/"+query_char 
    res = requests.get(url)
    
    if res.status_code!=200:
        raise RuntimeError(f"error fetching {res.status_code},check the api and try again")
    
    return res

#to read our response
def get_password_leaks_count(hashes,hash_to_check):
    hashes=(line.split(":")for line  in hashes.text.splitlines())
    for h,count in hashes:
        if h==hash_to_check:
            return count
    return 0
        

    
    

#check if password exists in api response

def pwned_api_check(password):
    sha1password = (hashlib.sha1(password.encode('utf-8')).hexdigest().upper())
    first_5chars, tail = sha1password[:5], sha1password[5:]
    
    response = request_api_data(first_5chars)
    print(response)
    return (get_password_leaks_count(response,tail))
    
    #hexdigest()=>returns a converted corresponding string object only hexadecimal digits
    #encode('utf-8')=>cuz unicode objs need to be encoded before hashing
    #upper(=>cuz sha1 hash format is digits and uppercaseletters only)



def main():
    flag=1

    
    while(flag==1):
        password=input("enter password to check")
        
        count=pwned_api_check(password)
        if count==1:
            t="time"
        else:
            t="times"
        if count:
                
            print(f"{password} was found {count}  {t}.... you should probably change the password")
        else:
            print(f"{password} was not found,carry on!")
        
        flag=int(input("do you want to try out other pwd? yes=1 for no=0"))
        
        
        if (flag==0):
            return "done"
    return "done"
    

print(main())
    

    
    

#why just a part of hash key passed as query char?for secure check    
#k anonimity => technique that allows somebody to recieve info about us yet not knowing who we are
#used by big tech companies as they use our personal data

#using our hash generator

#request_api_data("query_data")


#gave me response[400]   not good
#need near about 200