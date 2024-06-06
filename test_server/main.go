package main

import "net/http"

func main() {
	router := http.NewServeMux()
	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		msg := "My friendo"
		w.Write([]byte(msg))
	})
	http.ListenAndServe("localhost:4040", router)
}
