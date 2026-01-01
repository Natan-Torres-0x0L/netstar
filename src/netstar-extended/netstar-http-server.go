package main

import (
_ "crypto/tls"

  "net/http"
  "net"

  "time"
  "log"
  "fmt"
)

func NetstarHTTPServerHandleLogo(response http.ResponseWriter, request *http.Request) {
  response.Header().Set("Content-Type", "image/png")
  http.ServeFile(response, request, "share/server/netstar.png")
}

func NetstarHTTPServerHandleIcon(response http.ResponseWriter, request *http.Request) {
  response.Header().Set("Content-Type", "image/x-icon")
  http.ServeFile(response, request, "share/server/netstar.ico")
}

func NetstarHTTPServerHandle(response http.ResponseWriter, request *http.Request) {
  fmt.Println(request)
  http.ServeFile(response, request, "share/server/index.html")
}

func main() {
/*
  serverTLSCert, err := tls.LoadX509KeyPair("share/server/certificates/cert.pem", "share/server/certificates/key.pem")
  if err != nil {
    return
  }

  serverTLSConfig := &tls.Config{
    Certificates: []tls.Certificate{ serverTLSCert },
  }

  serverTLSListener, err := tls.Listen("tcp", ":8443", serverTLSConfig)
  if err != nil {
    return -1
  }
*/
  serverListener, err := net.Listen("tcp", ":8080")
  if err != nil {
    log.Fatalln(err)
  }

  serveMux := http.NewServeMux()
  serveMux.HandleFunc("/netstar.png", NetstarHTTPServerHandleLogo)
  serveMux.HandleFunc("/favicon.ico", NetstarHTTPServerHandleIcon)
  serveMux.HandleFunc("/", NetstarHTTPServerHandle)

  server := &http.Server{
    Handler:           serveMux,
    ReadTimeout:       3 * time.Second,
    ReadHeaderTimeout: 3 * time.Second,
//  WriteTimeout:      10 * time.Second,
    IdleTimeout:       3 * time.Second,
    MaxHeaderBytes:    1 << 20,
  }

  log.Println("[ netstar-http-server ] started")

  // go server.Serve(serverTLSListener)
  server.Serve(serverListener)
}
