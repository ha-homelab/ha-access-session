package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ha-homelab/ha-access-session/gateway"
)

var version = "development"

func main() {
	filename := flag.String("config", "gateway.json", "trusted administrator JSON configuration")
	listen := flag.String("listen", "127.0.0.1:8080", "HTTP listener behind a TLS Access proxy")
	certificate := flag.String("tls-cert", "", "PEM certificate chain for an HTTPS listener")
	privateKey := flag.String("tls-key", "", "private key for the HTTPS listener")
	showVersion := flag.Bool("version", false, "print release version")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}
	if (*certificate == "") != (*privateKey == "") {
		log.Fatal("both tls-cert and tls-key are required")
	}
	config, err := loadConfiguration(*filename)
	if err != nil {
		log.Fatal(err)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	handler, err := gateway.New(ctx, config)
	if err != nil {
		log.Fatal(err)
	}
	server := &http.Server{Addr: *listen, Handler: handler, ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32768}
	if *certificate != "" {
		server.TLSConfig, err = gateway.ServerTLSConfig(*certificate, *privateKey)
		if err != nil {
			log.Fatal("invalid gateway TLS certificate/key policy")
		}
	}
	go func() {
		<-ctx.Done()
		shutdown, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		_ = server.Shutdown(shutdown)
	}()
	log.Print("HA Access Session gateway started")
	if server.TLSConfig != nil {
		err = server.ListenAndServeTLS("", "")
	} else {
		err = server.ListenAndServe()
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal("gateway listener failed")
	}
}

// Keep startup diagnostics useful without printing paths, JSON fields or values.
func configurationOpenError(err error) error {
	category := "open_failed"
	if errors.Is(err, os.ErrNotExist) {
		category = "not_found"
	} else if errors.Is(err, os.ErrPermission) {
		category = "permission_denied"
	}
	return fmt.Errorf("cannot open gateway configuration (%s)", category)
}

func loadConfiguration(filename string) (gateway.Config, error) {
	var config gateway.Config
	file, err := os.Open(filename)
	if err != nil {
		return config, configurationOpenError(err)
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 65537))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return config, errors.New("invalid gateway configuration (invalid_json)")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return config, errors.New("invalid gateway configuration (trailing_data)")
	}
	return config, nil
}
