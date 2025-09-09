package com.example.crimealert;

@RestController
class HomeController {
    @GetMapping("/")
    public String home() { return "Crime Alert API is running ✅"; }
}
