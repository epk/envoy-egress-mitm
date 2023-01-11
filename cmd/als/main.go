package main

import (
	"io"
	"log"
	"net"

	"google.golang.org/grpc"

	envoy_service_accesslog_v3 "github.com/envoyproxy/go-control-plane/envoy/service/accesslog/v3"
)

type als struct{}

func (a *als) StreamAccessLogs(stream envoy_service_accesslog_v3.AccessLogService_StreamAccessLogsServer) error {
	for {
		req, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}

		for _, entry := range req.GetTcpLogs().GetLogEntry() {
			sni := entry.GetCommonProperties().GetTlsProperties().GetTlsSniHostname()

			log.Println("SNI:", sni)
			if err := createCert(sni); err != nil {
				log.Println("Error creating cert:", err)
			}
		}
	}
}

func main() {
	srv := grpc.NewServer()
	envoy_service_accesslog_v3.RegisterAccessLogServiceServer(srv, &als{})

	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Starting server")
	if err := srv.Serve(lis); err != nil {
		log.Fatal(err)
	}
}
