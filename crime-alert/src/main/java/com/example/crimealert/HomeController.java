package com.example.crimealert;

@RestController
class HomeController {
    @GetMapping("/")
    public String up() { return "API is up"; }
}

