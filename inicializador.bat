@echo off
title Lanzador Full-Stack PharmaDatum

echo ===================================================
echo   Iniciando Backend (FastAPI) y Frontend (Next.js)
echo ===================================================
echo.

:: 1. Iniciar FastAPI en una nueva ventana de consola
start "Servidor Backend - FastAPI (Puerto 8000)" cmd /k "cd /d F:\KAROL\PHARMADATUM\SCRIPTS && uvicorn main:app --reload --port 8000"

:: 2. Esperar 2 segundos a que el backend comience
timeout /t 2 /nobreak >nul

:: 3. Iniciar Next.js en otra ventana de consola
start "Servidor Frontend - Next.js (Puerto 3000)" cmd /k "cd /d F:\KAROL\PHARMADATUM\FRONT\tridatum-front && npm run dev" 

echo.
echo !Servidores lanzados con exito!
echo - Backend: http://127.0.0.1:8000
echo - Frontend: http://localhost:3000/app
echo.
pause