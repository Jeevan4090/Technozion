import React, { useRef } from "react";
import { Link } from "react-router-dom";
import { FiArrowUpRight } from "react-icons/fi";
import { gsap, useGSAP, motionConditions, observeSceneMeasurements } from "../../animation/gsap";
import TextReveal from "./TextReveal";
import ParallaxLayer from "./ParallaxLayer";
import { festival } from "../../data/festival";
import "./guest.css";

export default function GuestSpotlight() {
  const root = useRef(null);
  const { guest } = festival;
  useGSAP(() => {
    const mm = gsap.matchMedia();
    mm.add(motionConditions, ({ conditions }) => {
      if (conditions.reduce) return;
      gsap.fromTo(".guest-portrait-photo", { clipPath: "inset(100% 0 0 0)", scale: 1.15 }, { clipPath: "inset(0% 0 0 0)", scale: 1, duration: 1.1, ease: "power3.out", scrollTrigger: { trigger: ".guest-portrait", start: "top 80%", once: true } });
      gsap.fromTo(".guest-highlights li", { y: 24, opacity: 0 }, { y: 0, opacity: 1, duration: .6, stagger: .08, ease: "power2.out", scrollTrigger: { trigger: ".guest-highlights", start: "top 90%", once: true } });
      gsap.fromTo(".guest-portrait-frame", { rotate: -8, y: conditions.desktop ? 40 : 12 }, { rotate: 4, y: conditions.desktop ? -40 : -12, ease: "none", scrollTrigger: { trigger: root.current, start: "top bottom", end: "bottom top", scrub: true } });
    });
    const stopMeasuring = observeSceneMeasurements(root.current);
    return () => { stopMeasuring(); mm.revert(); };
  }, { scope: root });
  return <section className="festival-guest" id="guest" ref={root} aria-labelledby="guest-heading">
    <ParallaxLayer className="guest-outline" distance={55} aria-hidden="true">GUEST OF HONOUR</ParallaxLayer>
    <div className="guest-inner">
      <figure className="guest-portrait">
        <span className="guest-portrait-frame" aria-hidden="true" />
        <img className="guest-portrait-photo" src={guest.image} alt={"Portrait of " + guest.name} width="200" height="200" loading="lazy" decoding="async" />
        <figcaption>Guest of Honour</figcaption>
      </figure>
      <div className="guest-content">
        <p className="scene-eyebrow">02 / GUEST OF HONOUR · TECHNOZION ’26</p>
        <TextReveal id="guest-heading" className="guest-name">{guest.name.toUpperCase()}</TextReveal>
        <p className="guest-tagline">{guest.tagline}</p>
        <TextReveal as="p" mode="scrub" className="guest-bio">{guest.bio}</TextReveal>
        <ul className="guest-highlights">{guest.highlights.map(item => <li key={item}>{item}</li>)}</ul>
        <Link className="scene-link" to="/events">Join us at Technozion ’26 <FiArrowUpRight /></Link>
      </div>
    </div>
  </section>;
}
