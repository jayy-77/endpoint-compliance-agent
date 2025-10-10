package main

import (
	"fmt"
	"log"
	"compliance-agent/alerting"
)

func main2() {
	client := alerting.NewTeamsClient()
	if err := client.TestConnection(); err != nil {
		log.Fatalf("❌ Teams webhook test failed: %v", err)
	}
	fmt.Println("✅ Teams webhook test successful!")
}
