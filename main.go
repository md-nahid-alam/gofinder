//Author : Md Nahid Alam
package main

import (
    "encoding/json"
    "flag"
    "fmt"
    "io/ioutil"
    "net/http"
    "sync"
)

const apiKey = "10f746ffcb011d7de29ab0a67a292f368484b4a52dbf443cd455e2a3f184fcb1"

func main() {
    red := "\033[31m"
    green := "\033[32m"
    yellow := "\033[33m"
    reset := "\033[0m"
    var domain string


    flag.StringVar(&domain, "d", "", "domain name")


    var showStatus bool
    flag.BoolVar(&showStatus, "status", false, "Show status code of subdomains")


    var threadpool int
    flag.IntVar(&threadpool, "t", 0, "Number of threadpool")

    flag.Usage = func() {
          logo := red + `
_________     ____________       _________
__  ____/________  __/__(_)____________  /____________
_  / __ _  __ \_  /_ __  /__  __ \  __  /_  _ \_  ___/
/ /_/ / / /_/ /  __/ _  / _  / / / /_/ / /  __/  / `+ reset +`#> by [0xNahid]
` + red +
`\____/  \____//_/    /_/  /_/ /_/\__,_/  \___//_/`+ reset +` #> v1.0
`+ red +`---`+ yellow +`Super-fast golang based subdomain finding tool
`+ red +`------------------------------`+ yellow +`Master of Exploit
`+ red +`----------------------------------------------------------------------


 `+ green +` Usage: ` + green + `./gofinder` + green + ` -d <domain name> [-status] [-t <threadpool>]

 -d  ` + green + `Set the domain URL (www.google.com)
 -status  ` + green + `to show domains status code
 -t  ` + green + `thread to increase scanning speed

Visit our facebook group here:
  https://www.facebook.com/groups/officialehcommunity/

Follow on official telegram channel here:
  https://t.me/EHCommunityOfficial
` + reset
        fmt.Println(logo)
    }


    flag.Parse()

    if domain == "" {
        flag.Usage()
        return
    }


    url := fmt.Sprintf("https://www.virustotal.com/vtapi/v2/domain/report?apikey=%s&domain=%s", apiKey, domain)
    resp, err := http.Get(url)
    if err != nil {
        fmt.Println("")
        return
    }
    defer resp.Body.Close()


    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        fmt.Println("Something is wrong!! Try again")
        return
    }


    var data map[string]interface{}
    json.Unmarshal(body, &data)

var subdomainCount int
var status404Count int


if subdomains, ok := data["subdomains"].([]interface{}); ok {
    var wg sync.WaitGroup
    for _, sub := range subdomains {
        wg.Add(1)
        go func(sub string) {
            defer wg.Done()
            subdomainCount++
            if showStatus {

                subUrl := "http://" + sub
                subResp, subErr := http.Get(subUrl)
                if subErr != nil {
                    fmt.Println(sub + ": \033[31m[ HTTP Error ]\033[0m")
                } else {
                    fmt.Println(sub + ": \033[32m" + subResp.Status+"\033[0m")
                    if subResp.StatusCode == 404 {
                        status404Count++
                    }
                }
            } else{
                fmt.Println(sub)
            }
        }(sub.(string))
    }
    wg.Wait()
} else {
    fmt.Println("No subdomains found")
}
fmt.Println("")
fmt.Println(green+"--------------------------------------------------------------------")
fmt.Println(yellow+"Go-Finder v1.0                      https://t.me/EHCommunityOfficial")
fmt.Println(green+"--------------------------------------------------------------------")
fmt.Println(yellow+"Subdomains Found :", subdomainCount,"             404 status found : ", status404Count)
}
