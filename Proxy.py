# Include the libraries for socket and system calls
import socket
import sys
import os
import argparse
import re

# 1MB buffer size
BUFFER_SIZE = 1000000

# Get the IP address and Port number to use for this web proxy server
parser = argparse.ArgumentParser()
parser.add_argument('hostname', help='the IP Address Of Proxy Server')
parser.add_argument('port', help='the port number of the proxy server')
args = parser.parse_args()
proxyHost = args.hostname
proxyPort = int(args.port)

# Create a server socket, bind it to a port and start listening
try:
  # Create a server socket
  # ~~~~ INSERT CODE ~~~~

  # Create the TCP socket.
  from socket import *
  serverSocket = socket(AF_INET, SOCK_STREAM)

  # ~~~~ END CODE INSERT ~~~~
  print ('Created socket')
except:
  print ('Failed to create socket')
  sys.exit()

try:
  # Bind the the server socket to a host and port
  # ~~~~ INSERT CODE ~~~~

  # Bind the socket to the host and port (in a tuple) got from arguments.
  serverSocket.bind((proxyHost, proxyPort))

  # ~~~~ END CODE INSERT ~~~~
  print ('Port is bound')
except:
  print('Port is already in use')
  sys.exit()

try:
  # Listen on the server socket
  # ~~~~ INSERT CODE ~~~~

  # Start listening to TCP requests
  serverSocket.listen(1)

  # ~~~~ END CODE INSERT ~~~~
  print ('Listening to socket')
except:
  print ('Failed to listen')
  sys.exit()

# continuously accept connections
while True:
  print ('Waiting for connection...')
  clientSocket = None

  # Accept connection from client and store in the clientSocket
  try:
    # ~~~~ INSERT CODE ~~~~

    # Accepting a connection and storing it in clientSocket.
    clientSocket, addr = serverSocket.accept()

    # ~~~~ END CODE INSERT ~~~~
    print ('Received a connection')
  except:
    print ('Failed to accept connection')
    sys.exit()

  # Get HTTP request from client
  # and store it in the variable: message_bytes
  # ~~~~ INSERT CODE ~~~~

  # Getting all the bytes from the clientSocket connection's request, with a maximum request size.
  message_bytes = clientSocket.recv(BUFFER_SIZE)

  # ~~~~ END CODE INSERT ~~~~
  message = message_bytes.decode('utf-8')
  print ('Received request:')
  print ('< ' + message)

  # Extract the method, URI and version of the HTTP client request 
  requestParts = message.split()
  method = requestParts[0]
  URI = requestParts[1]
  version = requestParts[2]

  print ('Method:\t\t' + method)
  print ('URI:\t\t' + URI)
  print ('Version:\t' + version)
  print ('')

  # Get the requested resource from URI
  # Remove http protocol from the URI
  URI = re.sub('^(/?)http(s?)://', '', URI, count=1)

  # Remove parent directory changes - security
  URI = URI.replace('/..', '')

  # Split hostname from resource name
  resourceParts = URI.split('/', 1)
  hostname = resourceParts[0]
  resource = '/'

  if len(resourceParts) == 2:
    # Resource is absolute URI with hostname and resource
    resource = resource + resourceParts[1]

  print ('Requested Resource:\t' + resource)

  # Check if resource is in cache
  try:
    cacheLocation = './' + hostname + resource
    if cacheLocation.endswith('/'):
        cacheLocation = cacheLocation + 'default'

    print ('Cache location:\t\t' + cacheLocation)

    fileExists = os.path.isfile(cacheLocation)
    
    # Check wether the file is currently in the cache
    cacheFile = open(cacheLocation, "r")
    cacheData = cacheFile.readlines()
    if len(cacheData) == 0:
      raise Exception()

    print ('Cache hit! Loading from cache file: ' + cacheLocation)
    # ProxyServer finds a cache hit
    # Send back response to client 
    # ~~~~ INSERT CODE ~~~~

    # Check if client request is okay with a cached response.
    import email.utils
    for line in cacheData:
      tokens = line.split()
      header = tokens[0]
      if header == "Date:":
        
        dateStr = line.replace("Date: ", "")
        date = email.utils.parsedate_to_datetime(dateStr)
        currentDate = email.utils.localtime()
        responseAge = (currentDate - date).total_seconds()
        if responseAge >= 86400: # Also assume stale if response is 24 hours old.
          cacheFile.close()
          print("Stale response. Not sending to client.")
          raise Exception()


      elif header == "Cache-Control:":
        for token in tokens:
            maxAgeToken = token.find("max-age")
            if maxAgeToken != -1:
              maxAge = int(token.split('=')[1])
              
              if responseAge > maxAge:
                cacheFile.close()
                print("Stale response. Not sending to client.")
                raise Exception()



    # Send cached response to client.
    cacheDataFile = open(cacheLocation + '.DATA', 'rb') # binary
    clientSocket.send(cacheDataFile.read())
    cacheDataFile.close()

    cacheData = ''.join(cacheData)
    #cacheResponse = cacheData.encode()
    #clientSocket.send(cacheResponse)


    # ~~~~ END CODE INSERT ~~~~
    cacheFile.close()
    print ('Sent to the client:')
    print ('> ' + cacheData)
  except:
    # cache miss.  Get resource from origin server
    originServerSocket = None
    # Create a socket to connect to origin server
    # and store in originServerSocket
    # ~~~~ INSERT CODE ~~~~

    # Create TCP socket to connect to origin server.
    from socket import *
    originServerSocket = socket(AF_INET, SOCK_STREAM)
    import socket

    # ~~~~ END CODE INSERT ~~~~

    print ('Connecting to:\t\t' + hostname + '\n')
    try:
      # Get the IP address for a hostname
      address = socket.gethostbyname(hostname)
      # Connect to the origin server
      # ~~~~ INSERT CODE ~~~~

      # Connect to the requested host.
      originServerSocket.connect((hostname, 80))
      

      # ~~~~ END CODE INSERT ~~~~
      print ('Connected to origin Server')

      originServerRequest = ''
      originServerRequestHeader = ''
      # Create origin server request line and headers to send
      # and store in originServerRequestHeader and originServerRequest
      # originServerRequest is the first line in the request and
      # originServerRequestHeader is the second line in the request
      # ~~~~ INSERT CODE ~~~~

      # Request line is formatted "METHOD URI VERSION". URI is the resource, so resource = '/' means home page. 
      originServerRequest = method + ' ' + resource + ' ' + version
      # First header line is the host.
      originServerRequestHeader = "Host: " + hostname

      # ~~~~ END CODE INSERT ~~~~

      # Construct the request to send to the origin server
      request = originServerRequest + '\r\n' + originServerRequestHeader + '\r\n\r\n'

      # Request the web resource from origin server
      print ('Forwarding request to origin server:')
      for line in request.split('\r\n'):
        print ('> ' + line)

      try:
        originServerSocket.sendall(request.encode())
      except socket.error:
        print ('Forward request to origin failed')
        sys.exit()

      print('Request sent to origin server\n')

      # Get the response from the origin server
      # ~~~~ INSERT CODE ~~~~

      # Receive response.
      originServerResponse = originServerSocket.recv(BUFFER_SIZE)


      # ~~~~ END CODE INSERT ~~~~

      # Send the response to the client
      # ~~~~ INSERT CODE ~~~~

      # Send the retrieved response back to client on clientSocket now.
      clientSocket.send(originServerResponse)

      # ~~~~ END CODE INSERT ~~~~

      # Create a new file in the cache for the requested file.
      cacheDir, file = os.path.split(cacheLocation)
      print ('cached directory ' + cacheDir)
      if not os.path.exists(cacheDir):
        os.makedirs(cacheDir)
      cacheFile = open(cacheLocation, 'wb')

      # Save origin server response in the cache file
      # ~~~~ INSERT CODE ~~~~

      # Decode just the headers from origin server response
      headers = []
      for line in originServerResponse.splitlines(True):
        line = line.decode()
        if line == '\r\n':
          break
        headers.append(line)


      # Check if suitable to cache this response given the headers:
      shouldCache = True
      for line in headers:
        tokens = line.split()
        header = tokens[0]
      
        if header == "HTTP/1.1":
          responseCode = tokens[1]
          # Do not cache 301 or 302 responses, as it is not 'MUST' required in RFC.
          if responseCode in ("301", "302"):
            shouldCache = False

        elif header == "Cache-Control:":
          
          for token in tokens:
            if token == "no-store" or token == "no-cache" or token == "private":
              shouldCache = False


      if shouldCache:
        # Cache headers in original file, cache full response in new file
        cacheDataFile = open(cacheLocation + '.DATA', 'wb')
        contentList = originServerResponse.splitlines(True)
        headerList = []
        
        for line in contentList:
          if line == b'\r\n':
            break
          headerList.append(line)
            
        cacheFile.write(b''.join(headerList))
        cacheDataFile.write(b''.join(contentList))

        cacheDataFile.close()

      # ~~~~ END CODE INSERT ~~~~
      cacheFile.close()
      print ('cache file closed')

      # finished communicating with origin server - shutdown socket writes
      print ('origin response received. Closing sockets')
      originServerSocket.close()
       
      clientSocket.shutdown(socket.SHUT_WR)
      print ('client socket shutdown for writing')
    except OSError as err:
      print ('origin server request failed. ' + err.strerror)

  try:
    clientSocket.close()
  except:
    print ('Failed to close client socket')
