'use client';

import { useEffect, useRef } from 'react';

export default function SecureGlobe() {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    // Set initial size
    let width = canvas.width;
    let height = canvas.height;
    
    // Scale for retina displays
    const dpr = window.devicePixelRatio || 1;
    // We only set these once to avoid infinite loops if not handled carefully in resize
    canvas.width = 300 * dpr;
    canvas.height = 300 * dpr;
    ctx.scale(dpr, dpr);
    canvas.style.width = '300px';
    canvas.style.height = '300px';
    
    // Update local width/height for calculations (logical pixels)
    width = 300;
    height = 300;

    // Globe parameters
    // Reduced radius to prevent clipping of orbits
    const GLOBE_RADIUS = width * 0.28; 
    const DOT_RADIUS = 1.5;
    const DOT_COUNT = 350;
    const ROTATION_SPEED = 0.003;
    
    // Generate dots on a sphere using Fibonacci/Golden Angle
    interface Dot3D {
      x: number;
      y: number;
      z: number;
    }

    const dots: Dot3D[] = [];
    for (let i = 0; i < DOT_COUNT; i++) {
      const phi = Math.acos(1 - 2 * (i + 0.5) / DOT_COUNT);
      const theta = Math.PI * (1 + Math.sqrt(5)) * i;
      
      dots.push({
        x: GLOBE_RADIUS * Math.cos(theta) * Math.sin(phi),
        y: GLOBE_RADIUS * Math.sin(theta) * Math.sin(phi),
        z: GLOBE_RADIUS * Math.cos(phi)
      });
    }

    let rotation = 0;
    let animationFrameId: number;

    const render = () => {
      ctx.clearRect(0, 0, width, height);
      rotation += ROTATION_SPEED;

      const cx = width / 2;
      const cy = height / 2;

      // Project and sort dots
      const projectedDots = dots.map(dot => {
        // Rotate around Y axis
        const x = dot.x * Math.cos(rotation) - dot.z * Math.sin(rotation);
        const z = dot.x * Math.sin(rotation) + dot.z * Math.cos(rotation);
        const y = dot.y; // Keep Y as is
        
        // Tilt the globe slightly (X axis rotation)
        const tilt = 0.3; // radians
        const yRot = y * Math.cos(tilt) - z * Math.sin(tilt);
        const zRot = y * Math.sin(tilt) + z * Math.cos(tilt);

        // Perspective projection
        // Camera is at z = 300 + GLOBE_RADIUS
        const perspective = 400;
        const scale = perspective / (perspective + zRot); 
        
        const x2D = cx + x * scale;
        const y2D = cy + yRot * scale;
        
        return { 
            x: x2D, 
            y: y2D, 
            z: zRot, 
            scale, 
            original: dot 
        };
      });

      // Draw back-to-front
      projectedDots.sort((a, b) => b.z - a.z); // High Z is far away (if Z+ is into screen) 
      // Actually standard 3D: Z+ usually towards viewer, but here we did standard math where rotated Z+ is "back" depending on sign.
      // Let's rely on standard painters algo: draw furthest first.
      // In our rotation math: 
      // x' = x cos - z sin
      // z' = x sin + z cos
      // If z is positive, it depends on initial coords.
      // Let's just sort by projected Z (zRot).
      // If zRot is positive (further away/behind), draw first.
      
      projectedDots.forEach(dot => {
        // Alpha based on depth
        // Normalize zRot from [-R, R] to [0, 1] roughly
        // Front dots should be brighter.
        // Assuming zRot negative is closer (standard OpenGL) or positive?
        // Let's check visually. Usually we want "closer" to be opaque.
        // With `scale = perspective / (perspective + zRot)`, larger zRot means smaller scale (further away).
        // So large positive zRot is FAR. Small/Negative zRot is CLOSE.
        
        const depth = (dot.z + GLOBE_RADIUS) / (2 * GLOBE_RADIUS); // 0 to 1 roughly
        // If zRot is large (far), depth is close to 1. If zRot is -R (close), depth is 0.
        // We want opacity high when close (zRot is small/negative).
        
        const opacity = Math.max(0.15, 1 - depth * 0.8);
        const size = Math.max(0.5, DOT_RADIUS * dot.scale);

        ctx.beginPath();
        ctx.arc(dot.x, dot.y, size, 0, Math.PI * 2);
        
        // Color theme: Slate/Blue
        // Use a brighter blue for front, darker for back
        if (dot.z < 0) {
            // Front
            ctx.fillStyle = `rgba(96, 165, 250, ${opacity})`; // blue-400
        } else {
            // Back
            ctx.fillStyle = `rgba(51, 65, 85, ${opacity})`; // slate-700
        }
        
        ctx.fill();
      });

      // Draw outer shield/scanner rings
      const time = Date.now() / 1000;
      
      // Pulse effect (Ripple 1)
      const pulse1 = 1 + Math.sin(time * 2) * 0.05;
      ctx.beginPath();
      ctx.arc(cx, cy, GLOBE_RADIUS * 1.2 * pulse1, 0, Math.PI * 2);
      ctx.strokeStyle = `rgba(59, 130, 246, ${0.1 + Math.sin(time) * 0.05})`;
      ctx.lineWidth = 1;
      ctx.stroke();

      // Atomic Orbits (Electrons)
      // Star Pattern: One horizontal, two crossed like swords (X)
      const orbits = [
        { rotX: 0, rotY: 0, rotZ: 0, speed: 1.5, phase: 0 }, // Horizontal Straight
        { rotX: 0, rotY: 0, rotZ: Math.PI / 3, speed: 1.5, phase: 2 }, // Crossed / (60 deg)
        { rotX: 0, rotY: 0, rotZ: -Math.PI / 3, speed: 1.5, phase: 4 }, // Crossed \ (-60 deg)
      ];

      orbits.forEach((orbit, i) => {
        // Draw Orbit Path
        ctx.beginPath();
        const segments = 64;
        for (let j = 0; j <= segments; j++) {
          const theta = (j / segments) * Math.PI * 2;
          // Base circle in X-Z plane (horizontal)
          let ox = Math.cos(theta) * GLOBE_RADIUS * 1.5;
          let oy = 0;
          let oz = Math.sin(theta) * GLOBE_RADIUS * 1.5;
          
          // Apply Orbit Rotation
          // We need Z-rotation to create the "star" pattern from front view
          // Z-rotation rotates around the Z-axis (coming out of screen)
          
          // 1. Rotate Z (Tilt the plane itself to make X shape)
          let x0 = ox * Math.cos(orbit.rotZ) - oy * Math.sin(orbit.rotZ);
          let y0 = ox * Math.sin(orbit.rotZ) + oy * Math.cos(orbit.rotZ);
          let z0 = oz; // Z doesn't change with Z-rotation? Wait.
          // If we rotate the X-Z plane around Z axis:
          // ox is on X axis. oy is 0.
          // New X axis is rotated. New Y axis is rotated.
          // Point (ox, 0, oz) -> (ox * cos - 0, ox * sin + 0, oz)
          // So y becomes non-zero. The ring lifts up/down.
          // Correct.

          // 2. Rotate X (optional extra tilt from config)
          let y1 = y0 * Math.cos(orbit.rotX) - z0 * Math.sin(orbit.rotX);
          let z1 = y0 * Math.sin(orbit.rotX) + z0 * Math.cos(orbit.rotX);
          let x1 = x0;
          
          // 3. Rotate Y (optional extra tilt from config)
          let x2 = x1 * Math.cos(orbit.rotY) - z1 * Math.sin(orbit.rotY);
          let z2 = x1 * Math.sin(orbit.rotY) + z1 * Math.cos(orbit.rotY);
          let y2 = y1;

          // Apply Global Tilt (same as dots)
          const tilt = 0.3;
          const yRot = y2 * Math.cos(tilt) - z2 * Math.sin(tilt);
          const zRot = y2 * Math.sin(tilt) + z2 * Math.cos(tilt);
          const xRot = x2;

          // Project
          const perspective = 400;
          const scale = perspective / (perspective + zRot);
          const x2D = cx + xRot * scale;
          const y2D = cy + yRot * scale;
          
          if (j === 0) ctx.moveTo(x2D, y2D);
          else ctx.lineTo(x2D, y2D);
        }
        ctx.strokeStyle = `rgba(147, 197, 253, 0.3)`; // blue-300
        ctx.lineWidth = 1;
        ctx.stroke();

        // Draw Electron
        const electronTheta = time * orbit.speed + orbit.phase;
        let ex = Math.cos(electronTheta) * GLOBE_RADIUS * 1.5;
        let ey = 0;
        let ez = Math.sin(electronTheta) * GLOBE_RADIUS * 1.5;
        
        // 1. Rotate Z
        let ex0 = ex * Math.cos(orbit.rotZ) - ey * Math.sin(orbit.rotZ);
        let ey0 = ex * Math.sin(orbit.rotZ) + ey * Math.cos(orbit.rotZ);
        let ez0 = ez;

        // 2. Rotate X
        let ey1 = ey0 * Math.cos(orbit.rotX) - ez0 * Math.sin(orbit.rotX);
        let ez1 = ey0 * Math.sin(orbit.rotX) + ez0 * Math.cos(orbit.rotX);
        let ex1 = ex0;
        
        // 3. Rotate Y
        let ex2 = ex1 * Math.cos(orbit.rotY) - ez1 * Math.sin(orbit.rotY);
        let ez2 = ex1 * Math.sin(orbit.rotY) + ez1 * Math.cos(orbit.rotY);
        let ey2 = ey1;

        // Global Tilt
        const tilt = 0.3;
        const eyRot = ey2 * Math.cos(tilt) - ez2 * Math.sin(tilt);
        const ezRot = ey2 * Math.sin(tilt) + ez2 * Math.cos(tilt);
        const exRot = ex2;

        // Project
        const perspective = 400;
        const escale = perspective / (perspective + ezRot);
        const ex2D = cx + exRot * escale;
        const ey2D = cy + eyRot * escale;
        
        ctx.beginPath();
        ctx.arc(ex2D, ey2D, 3 * escale, 0, Math.PI * 2);
        ctx.fillStyle = '#60a5fa'; // blue-400
        ctx.shadowColor = '#3b82f6';
        ctx.shadowBlur = 8;
        ctx.fill();
        ctx.shadowBlur = 0;
      });

      animationFrameId = requestAnimationFrame(render);
    };

    render();

    return () => {
      cancelAnimationFrame(animationFrameId);
    };
  }, []);

  return (
    <div className="relative flex items-center justify-center w-56 h-56 sm:w-64 sm:h-64">
        {/* Glow effect background */}
        <div className="absolute inset-0 bg-blue-500/10 blur-3xl rounded-full animate-pulse" />
        <canvas 
            ref={canvasRef} 
            className="relative z-10"
        />
    </div>
  );
}
