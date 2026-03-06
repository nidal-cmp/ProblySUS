import React, { useRef, useState, useEffect, useMemo } from 'react';
import { motion, useMotionValue, useTransform, useSpring, AnimatePresence } from 'framer-motion';

// Utility for random numbers
const random = (min, max) => Math.random() * (max - min) + min;

const BackgroundStar = ({ index, mouseX, mouseY }) => {
    const depth = useMemo(() => random(0.01, 0.05), []);
    const size = useMemo(() => random(0.5, 2), []);
    const initialX = useMemo(() => random(0, 100), []);
    const initialY = useMemo(() => random(0, 100), []);
    const duration = useMemo(() => random(3, 8), []);
    const delay = useMemo(() => random(0, 5), []);

    const x = useTransform(mouseX, [0, window.innerWidth], [-20 * depth, 20 * depth]);
    const y = useTransform(mouseY, [0, window.innerHeight], [-20 * depth, 20 * depth]);

    return (
        <motion.div
            className="absolute bg-white rounded-full"
            style={{
                width: size,
                height: size,
                left: `${initialX}%`,
                top: `${initialY}%`,
                x,
                y,
                opacity: 0.6,
                willChange: 'transform', // Hardware acceleration
            }}
            animate={{
                opacity: [0.3, 0.8, 0.3],
            }}
            transition={{
                duration: duration,
                repeat: Infinity,
                ease: "easeInOut",
                delay: delay,
            }}
        />
    );
};

const InteractiveStar = ({ mouseX, mouseY }) => {
    const initialX = useMemo(() => Math.random() * window.innerWidth, []);
    const initialY = useMemo(() => Math.random() * window.innerHeight, []);
    const size = useMemo(() => random(2, 4), []);

    // Optimization: Stiff spring for instant response (less drag/lag feel)
    const springConfig = { stiffness: 150, damping: 15, mass: 0.1 };
    const x = useSpring(initialX, springConfig);
    const y = useSpring(initialY, springConfig);

    useEffect(() => {
        const handleMouseMove = () => {
            const dx = mouseX.get() - initialX;
            const dy = mouseY.get() - initialY;
            const distance = Math.sqrt(dx * dx + dy * dy);
            const limit = 250;

            if (distance < limit) {
                const force = (limit - distance) / limit;
                const angle = Math.atan2(dy, dx);

                const moveDistance = force * 150;

                const moveX = Math.cos(angle) * moveDistance * -1;
                const moveY = Math.sin(angle) * moveDistance * -1;

                x.set(initialX + moveX);
                y.set(initialY + moveY);
            } else {
                x.set(initialX);
                y.set(initialY);
            }
        };

        const unsubscribeX = mouseX.on("change", handleMouseMove);
        const unsubscribeY = mouseY.on("change", handleMouseMove);
        return () => { unsubscribeX(); unsubscribeY(); };
    }, [mouseX, mouseY, initialX, initialY, x, y]);

    return (
        <motion.div
            style={{
                x,
                y,
                width: size,
                height: size,
                backgroundColor: 'white',
                borderRadius: '50%',
                position: 'absolute',
                top: 0,
                left: 0,
                willChange: 'transform', // Hardware acceleration
                boxShadow: `0 0 ${size * 1.5}px rgba(255, 255, 255, 0.8)`,
            }}
            animate={{
                opacity: [0.6, 1, 0.6],
                scale: [1, 1.2, 1]
            }}
            transition={{
                duration: random(3, 7),
                repeat: Infinity,
                delay: random(0, 2),
                ease: "easeInOut"
            }}
        />
    );
};

const Comet = () => {
    const [comets, setComets] = useState([]);

    useEffect(() => {
        const spawnComet = () => {
            const id = Date.now();
            const side = Math.floor(random(0, 4)); // 0: Top, 1: Right, 2: Bottom, 3: Left
            let startX, startY, endX, endY, angle;

            const buffer = 100;
            const width = window.innerWidth;
            const height = window.innerHeight;

            // Determine Start Position
            switch (side) {
                case 0: // Top
                    startX = random(0, width);
                    startY = -buffer;
                    endX = random(0, width);
                    endY = height + buffer;
                    break;
                case 1: // Right
                    startX = width + buffer;
                    startY = random(0, height);
                    endX = -buffer;
                    endY = random(0, height);
                    break;
                case 2: // Bottom
                    startX = random(0, width);
                    startY = height + buffer;
                    endX = random(0, width);
                    endY = -buffer;
                    break;
                case 3: // Left
                    startX = -buffer;
                    startY = random(0, height);
                    endX = width + buffer;
                    endY = random(0, height);
                    break;
                default: break;
            }

            // Calculate Angle
            const dx = endX - startX;
            const dy = endY - startY;
            // Angle in degrees for rotation. 
            // Note: CSS rotation 0 is usually pointing right (depending on element). 
            // Our comet tail needs to trail behind.
            // Atan2 returns radians.
            const angleRad = Math.atan2(dy, dx);
            angle = angleRad * (180 / Math.PI);

            const size = random(3, 5); // Base size
            const duration = random(1.5, 3); // Slower for majesty

            setComets(prev => [...prev, { id, startX, startY, endX, endY, angle, size, duration }]);

            setTimeout(() => {
                setComets(prev => prev.filter(c => c.id !== id));
            }, duration * 1000 + 100);
        };

        const interval = setInterval(spawnComet, 800); // Frequent spawns

        // Initial spawn
        spawnComet();

        return () => clearInterval(interval);
    }, []);

    return (
        <AnimatePresence>
            {comets.map(comet => (
                <motion.div
                    key={comet.id}
                    className="absolute bg-white rounded-full z-0 blur-[1px]"
                    style={{
                        width: comet.size,
                        height: comet.size,
                        left: 0,
                        top: 0,
                        boxShadow: `0 0 15px 4px rgba(255, 255, 255, 0.9)`,
                    }}
                    initial={{ x: comet.startX, y: comet.startY, opacity: 0 }}
                    animate={{ x: comet.endX, y: comet.endY, opacity: [0, 1, 1, 0] }}
                    exit={{ opacity: 0 }}
                    transition={{ duration: comet.duration, ease: "linear" }}
                >
                    {/* Tail */}
                    <div
                        className="absolute top-1/2 left-1/2 w-[200px] h-[2px] bg-gradient-to-r from-transparent via-white to-transparent origin-left opacity-60"
                        style={{
                            transform: `translate(-50%, -50%) rotate(${comet.angle + 180}deg) translateX(100px)`, // Offset to trail behind
                        }}
                    />
                </motion.div>
            ))}
        </AnimatePresence>
    );
};

const AntigravityParams = ({ children }) => {
    const mouseX = useMotionValue(0);
    const mouseY = useMotionValue(0);

    const handleMouseMove = (e) => {
        mouseX.set(e.clientX);
        mouseY.set(e.clientY);
    };

    const [mounted, setMounted] = useState(false);
    useEffect(() => setMounted(true), []);

    if (!mounted) return null;

    return (
        <div
            className="relative min-h-screen w-full bg-black text-white selection:bg-white selection:text-black"
            onMouseMove={handleMouseMove}
        >
            {/* Background Stars (Parallax only) — fixed so they persist while scrolling */}
            <div className="fixed inset-0 z-0 pointer-events-none overflow-hidden">
                {Array.from({ length: 300 }).map((_, i) => (
                    <BackgroundStar key={`bg-star-${i}`} index={i} mouseX={mouseX} mouseY={mouseY} />
                ))}
            </div>

            {/* Comets Layer — fixed */}
            <div className="fixed inset-0 z-0 pointer-events-none overflow-hidden">
                <Comet />
            </div>

            {/* Interactive Stars (Foreground) — fixed */}
            <div className="fixed inset-0 z-0 pointer-events-none overflow-hidden">
                {Array.from({ length: 200 }).map((_, i) => (
                    <InteractiveStar key={`fg-star-${i}`} mouseX={mouseX} mouseY={mouseY} />
                ))}
            </div>

            {/* Content */}
            <div className="relative z-10 w-full min-h-screen flex flex-col items-center justify-start">
                {children}
            </div>
        </div>
    );
};

export default AntigravityParams;
