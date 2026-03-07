#!/usr/bin/env python3
"""
Load Controller - Modes de génération avancés

Importé depuis nxlog_simulator.py
Fonctionnalités:
- Mode RAMP: Montée progressive du débit
- Mode BURST: Pics aléatoires de trafic
- Mode CONSTANT: Débit fixe
"""

import random
import time
import threading
from typing import List, Optional, Callable
from datetime import datetime

from core import RateLimiter, LogEvent, OutputHandler


class LoadController:
    """
    Contrôleur de charge pour modes avancés de génération.
    
    Modes supportés:
    - constant: Débit fixe
    - ramp: Montée progressive (start_eps → max_eps)
    - burst: Pics aléatoires de trafic
    """
    
    def __init__(self, start_eps: float, max_eps: float, ramp_duration: int, mode: str = "ramp"):
        """
        Initialise le contrôleur.
        
        Args:
            start_eps: EPS de départ
            max_eps: EPS maximum
            ramp_duration: Durée de montée en secondes
            mode: constant, ramp, ou burst
        """
        self.start_eps = start_eps
        self.max_eps = max_eps
        self.ramp_duration = ramp_duration
        self.mode = mode
        self.start_time = time.time()
        self.current_eps = start_eps
        
    def update(self) -> float:
        """
        Met à jour le débit courant selon le mode.
        
        Returns:
            EPS actuel à utiliser
        """
        if self.mode == "constant":
            return self.max_eps
            
        elif self.mode == "ramp":
            if self.ramp_duration <= 0:
                return self.max_eps
                
            elapsed = time.time() - self.start_time
            if elapsed >= self.ramp_duration:
                return self.max_eps
                
            progress = elapsed / self.ramp_duration
            self.current_eps = self.start_eps + (self.max_eps - self.start_eps) * progress
            return self.current_eps
            
        elif self.mode == "burst":
            # 5% chance de pic
            if random.random() < 0.05:
                self.current_eps = random.uniform(self.start_eps, self.max_eps)
            else:
                self.current_eps = self.start_eps
            return self.current_eps
            
        else:
            return self.max_eps
    
    def get_stats(self) -> str:
        """Retourne les statistiques courantes."""
        elapsed = time.time() - self.start_time
        if self.mode == "ramp":
            progress = min(100, (elapsed / self.ramp_duration) * 100) if self.ramp_duration > 0 else 100
            return f"Target: {self.current_eps:.1f} EPS | Progress: {progress:.0f}%"
        else:
            return f"Target: {self.current_eps:.1f} EPS | Mode: {self.mode}"


class StatsReporter(threading.Thread):
    """
    Affichage temps réel des statistiques de génération.
    
    Importé depuis nxlog_simulator.py
    """
    
    def __init__(self, outputs: List[OutputHandler], controller: LoadController, interval: int = 5):
        """
        Initialise le reporter de stats.
        
        Args:
            outputs: Liste des handlers de sortie
            controller: Contrôleur de charge
            interval: Intervalle d'affichage en secondes
        """
        super().__init__(daemon=True)
        self.outputs = outputs
        self.controller = controller
        self.interval = interval
        self.running = True
        self.last_sent = 0
        self.last_time = time.time()
        self.total_stats = {"sent": 0, "errors": 0}
        
    def run(self):
        """Boucle d'affichage des statistiques."""
        while self.running:
            time.sleep(self.interval)
            now = time.time()
            elapsed = now - self.last_time
            
            # Calculer les stats
            total_sent = getattr(self, '_total_sent', 0)
            total_errors = getattr(self, '_total_errors', 0)
            
            current_eps = (total_sent - self.last_sent) / elapsed if elapsed > 0 else 0
            
            print(f"\n[STATS] {datetime.now().strftime('%H:%M:%S')} | "
                  f"{self.controller.get_stats()} | "
                  f"Current: {current_eps:.1f} EPS | "
                  f"Total: {total_sent:,} | "
                  f"Errors: {total_errors}")
            
            self.last_sent = total_sent
            self.last_time = now
    
    def update_stats(self, sent: int, errors: int):
        """Met à jour les statistiques (appelé par le générateur)."""
        self._total_sent = sent
        self._total_errors = errors
    
    def stop(self):
        """Arrête le reporter."""
        self.running = False


class MultiClientGenerator:
    """
    Générateur avec multiple clients parallèles.
    
    Importé depuis nxlog_simulator.py - Support multi-threading
    """
    
    def __init__(self, outputs: List[OutputHandler], generator_fn: Callable, controller: LoadController):
        """
        Initialise le générateur multi-client.
        
        Args:
            outputs: Liste des handlers de sortie
            generator_fn: Fonction de génération d'événements
            controller: Contrôleur de charge
        """
        self.outputs = outputs
        self.generator_fn = generator_fn
        self.controller = controller
        self.current_client = 0
        self.total_sent = 0
        self.total_errors = 0
        
    def generate_and_send(self) -> bool:
        """
        Génère un événement et l'envoie au client suivant.
        
        Returns:
            True si succès, False sinon
        """
        event = self.generator_fn()
        output = self.outputs[self.current_client]
        
        success = output.write(event)
        if success:
            self.total_sent += 1
        else:
            self.total_errors += 1
            
        # Round-robin entre les clients
        self.current_client = (self.current_client + 1) % len(self.outputs)
        
        return success
    
    def get_stats(self) -> dict:
        """Retourne les statistiques courantes."""
        return {
            "sent": self.total_sent,
            "errors": self.total_errors,
            "active_clients": len(self.outputs)
        }
