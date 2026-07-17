from __future__ import annotations

from eval.multilang.build_verify import generate_containerfile


class TestGenerateContainerfile:
    def test_go_containerfile(self):
        cf = generate_containerfile("go", "golang:1.21", "/src")
        assert "FROM golang:1.21" in cf
        assert "go build ./..." in cf
        assert "go test ./..." in cf

    def test_python_containerfile(self):
        cf = generate_containerfile("python", "python:3.11", "/src")
        assert "FROM python:3.11" in cf
        assert "pip install" in cf

    def test_javascript_containerfile(self):
        cf = generate_containerfile("javascript", "node:20", "/src")
        assert "FROM node:20" in cf
        assert "npm install" in cf

    def test_java_containerfile(self):
        cf = generate_containerfile("java", "maven:3.9-eclipse-temurin-17", "/src")
        assert "FROM maven" in cf
        assert "mvn" in cf

    def test_rust_containerfile(self):
        cf = generate_containerfile("rust", "rust:1.75", "/src")
        assert "FROM rust:1.75" in cf
        assert "cargo build" in cf

    def test_python_containerfile_with_requirements(self):
        cf = generate_containerfile("python", "python:3.11", "/src",
                                    has_requirements_txt=True, has_setup_py=False)
        assert "requirements.txt" in cf
