package main

import "fmt"

func handleRequest(input string) string {
    return processData(input)
}

func processData(data string) string {
    fmt.Println(data)
    return data
}

func main() {
    handleRequest("test")
}
