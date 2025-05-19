# coin-server

A server  for all the classmates in CS521 to  mine for 521COIN!     


## Learning Outcomes

To become more familiar with:    
    
1.   The pthread library and parallelization using threads   
2.   The producer/consumer paradigm    
3.   Network programming with sockets    
4.   Performance measurement
5.   Introduction to proto buff

 
## Concept      
    
When the client connects  to the server, it will first request a task. Then the server will create the task and send it back to the client. Once the task is received, the client can work on "mining", find a solution, and send it back to the server. The server will verify whether the solution is correct and send this boolean value back to the client. If the verification is True, the client can mine again!        

![Image](https://github.com/user-attachments/assets/81d0d372-a709-4c5e-bfda-1dd7e356a7f8)  



## Steps
  

client --> requests task --> server    
server --> gives task --> client        
client works on it       
client --> sends solution --> server    
server verifies     
server --> sends verification --> client     



## Build and Run

1. **Compile**
   ```bash  
   make    

2. **Run Server**   
   ```bash
   ./coin-server port 

port can be any four-digit number greater than 1024.

Optional additional arguments:

[-s seed] [-a adjective_file] [-n animal_file] [-l log_file]          
    
    * -s    Specify the seed number       
    * -a    Specify the adjective file to be used       
    * -n    Specify the animal file to be used       
    * -l    Specify the log file to be used      
    
3. **Run Client**
   ```bash
   ./client localhost port username

port should be the same port used to run the server.
username can be any sequence of 24 characters. 

## Running + Example Usage

![example](https://github.com/weicheng112/coin-server/assets/108167692/dbaf71ab-e129-44ae-99f0-5d02ed344a58)    
         
           
This picture shows our client requesting the task and starting to work on it. After that, the client will send the solution to the server.    
![example2](https://github.com/weicheng112/coin-server/assets/108167692/dd146ae1-8fe8-4abb-90c4-7c625812da21)     
          
            
This picture shows that the server received the request from the client. Then it sends the task to the client immediately. After the server gets the solution sent by the client, it will verify the solution and send the verification result back to the client.    

## Usage of Proto Buff
Protocol buffers are Google’s language-neutral, platform-neutral, extensible mechanism for serializing structured data. The data is defined in coin-message.proto and compiled into C-code using protoc --c_out= proto compiler. 

In server.c, you can see how the defined envelope in coin-message.proto is used.

The generated C type CoinMsg__Envelope has a union-like payload field (one‐of), so you can send or receive any of the message kinds through exactly one socket call.

When you call your helper recv_envelope(fd), it reads the length prefix , unpacks the bytes into a CoinMsg__Envelope struct, and checks body_case so you know which type of messges is sent and call corresponding handler to handle the messages.

In short, proto buff provides auto generated functions and structs based on proto file and you can focus implementation instead of network transferring.




