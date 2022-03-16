package main

type CheckerFunc func(string) (bool, []string, error)
