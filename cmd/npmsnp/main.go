package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"npmsnp/pkg/config"
	"npmsnp/pkg/db"
	"npmsnp/pkg/handlers"
	"npmsnp/pkg/protocol"
	"npmsnp/pkg/services"
)

func main() {
	cfg := config.Load()

	hostFlag := flag.String("host", cfg.BindHost, "Bind host IP")
	externalHostFlag := flag.String("external-host", cfg.ExternalHost, "Reported public/LAN host IP")
	nsPortFlag := flag.Int("ns-port", cfg.NSPort, "Notification Server port")
	sbPortFlag := flag.Int("sb-port", cfg.SBPort, "Switchboard Server port")
	httpPortFlag := flag.Int("http-port", cfg.HTTPPort, "HTTP / Web Dashboard port")
	dbPathFlag := flag.String("db", cfg.DBPath, "Path to database.db")
	debugFlag := flag.Bool("debug", false, "Enable debug logging")

	flag.Parse()

	if *debugFlag {
		log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile)
	} else {
		log.SetFlags(log.Ldate | log.Ltime)
	}

	absDBPath, _ := filepath.Abs(*dbPathFlag)
	database, err := db.NewDatabase(absDBPath, cfg.DBSecretKey)
	if err != nil {
		log.Fatalf("[FATAL] Failed to initialize database at %s: %v", absDBPath, err)
	}
	defer database.Close()

	_ = database.EnsureServiceAccount(cfg.ServiceAccountEmail, cfg.ServiceAccountName)

	authMgr := protocol.NewAuthManager(cfg.DBSecretKey)
	sessionMgr := services.NewSessionManager(database)
	sbMgr := services.NewSwitchboardManager(authMgr)

	httpServer := services.NewHTTPServer(
		*hostFlag,
		*httpPortFlag,
		*externalHostFlag,
		database,
		authMgr,
		sessionMgr,
		sbMgr,
		cfg.AutoRegisterUnknownUsers,
		cfg.AdminPassword,
	)
	if err := httpServer.Start(); err != nil {
		log.Fatalf("[FATAL] Failed to start HTTP server on %s:%d: %v", *hostFlag, *httpPortFlag, err)
	}
	defer httpServer.Stop()

	// Start NS TCP listener
	nsAddr := fmt.Sprintf("%s:%d", *hostFlag, *nsPortFlag)
	nsListener, err := net.Listen("tcp", nsAddr)
	if err != nil {
		log.Fatalf("[FATAL] Failed to listen on NS port %s: %v", nsAddr, err)
	}
	defer nsListener.Close()

	// Start SB TCP listener
	sbAddr := fmt.Sprintf("%s:%d", *hostFlag, *sbPortFlag)
	sbListener, err := net.Listen("tcp", sbAddr)
	if err != nil {
		log.Fatalf("[FATAL] Failed to listen on SB port %s: %v", sbAddr, err)
	}
	defer sbListener.Close()

	// Banner
	banner := fmt.Sprintf(`
=================================================================
  _   _ _____  __  __ _____ _   _ _____  
 | \ | |  __ \|  \/  / ____| \ | |  __ \ 
 |  \| | |__) | \  / | (___ |  \| | |__) |
 | . `+"`"+` |  ___/| |\/| |\___ \| . `+"`"+` |  ___/ 
 | |\  | |    | |  | |____) | |\  | |     
 |_| \_|_|    |_|  |_|_____/|_| \_|_|     
=================================================================
  Project: %s | %s (Go Engine) v%s RUNNING
=================================================================
  * Project Name            : %s
  * Notification Server (NS): %s:%d
  * Switchboard Server  (SB): %s:%d (Chats & Messaging)
  * Web Admin Dashboard     : http://%s:%d/
  * SQLite Database         : %s
=================================================================
  [NOTE FOR LINUX / REMOTE / LAN]:
  - Both port %d (NS) AND port %d (SB / Chats) must be OPEN in firewall:
      sudo ufw allow %d/tcp && sudo ufw allow %d/tcp
  - If clients cannot exchange messages, specify:
      ./npmsnp --external-host <YOUR_IP>
=================================================================
`, cfg.ProjectName, cfg.ServerName, cfg.ServerVersion,
		cfg.ProjectName,
		*externalHostFlag, *nsPortFlag,
		*externalHostFlag, *sbPortFlag,
		*externalHostFlag, *httpPortFlag,
		absDBPath,
		*nsPortFlag, *sbPortFlag,
		*nsPortFlag, *sbPortFlag,
	)

	fmt.Print(banner)

	// NS accept loop
	go func() {
		for {
			conn, err := nsListener.Accept()
			if err != nil {
				return
			}
			handler := handlers.NewNSClientHandler(
				conn,
				database,
				authMgr,
				sessionMgr,
				sbMgr,
				*externalHostFlag,
				*nsPortFlag,
				*sbPortFlag,
				*httpPortFlag,
			)
			go handler.Run()
		}
	}()

	// SB accept loop
	go func() {
		for {
			conn, err := sbListener.Accept()
			if err != nil {
				return
			}
			handler := handlers.NewSBClientHandler(
				conn,
				database,
				authMgr,
				sessionMgr,
				sbMgr,
				*externalHostFlag,
				*sbPortFlag,
				*httpPortFlag,
			)
			go handler.Run()
		}
	}()

	// Wait for interrupt
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	log.Printf("[INFO] Stopping %s Server...", cfg.ProjectName)
}
