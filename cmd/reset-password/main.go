package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"npmsnp/pkg/config"
	"npmsnp/pkg/db"
)

func main() {
	cfg := config.Load()

	dbPathFlag := flag.String("db", cfg.DBPath, "Path to database.db")
	listFlag := flag.Bool("list", false, "List all registered users and decrypted passwords")
	flag.Parse()

	absDBPath, _ := filepath.Abs(*dbPathFlag)
	database, err := db.NewDatabase(absDBPath, cfg.DBSecretKey)
	if err != nil {
		fmt.Printf("[ERROR] Failed to open database at %s: %v\n", absDBPath, err)
		os.Exit(1)
	}
	defer database.Close()

	if *listFlag {
		users, err := database.GetAllUsers()
		if err != nil {
			fmt.Printf("[ERROR] Failed to fetch users: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("\nRegistered users in %s (%d total):\n", absDBPath, len(users))
		fmt.Println(strings.Repeat("-", 75))
		fmt.Printf("%-30s | %-20s | %s\n", "Email", "Friendly Name", "Password")
		fmt.Println(strings.Repeat("-", 75))
		for _, u := range users {
			fmt.Printf("%-30s | %-20s | %s\n", u.Email, u.FriendlyName, u.Password)
		}
		fmt.Println(strings.Repeat("-", 75))
		fmt.Println()
		return
	}

	args := flag.Args()
	if len(args) < 2 {
		fmt.Println("Usage:")
		fmt.Println("  reset-password <email> <new_password>")
		fmt.Println("  reset-password --list")
		return
	}

	email := strings.TrimSpace(args[0])
	newPassword := strings.TrimSpace(args[1])

	if !strings.Contains(email, "@") {
		fmt.Printf("[ERROR] Invalid email: %s\n", email)
		os.Exit(1)
	}

	user, _ := database.GetUser(email)
	if user == nil {
		_, err = database.CreateUser(email, newPassword, "")
		if err != nil {
			fmt.Printf("[ERROR] Failed to create user: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[OK] User %s created successfully with password '%s'.\n", email, newPassword)
	} else {
		err = database.UpdatePassword(email, newPassword)
		if err != nil {
			fmt.Printf("[ERROR] Failed to update password: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[OK] Password for %s updated successfully to '%s'.\n", email, newPassword)
	}
}
