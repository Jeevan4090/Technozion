import { orderEvents } from "./eventOrder";
import { selectFeaturedEvents } from "./featuredEvents";
import { getFallbackEvents } from "./eventsData";

test("prioritizes SDC Games and every CSE Society event ahead of other posters without mutating data", () => {
  const events = [
    { name: "Other", imgsrc: "/other.jpg" },
    { name: "AI Unveiled", club: "CSE Society", imgsrc: "" },
    { name: "SDC Games", imgsrc: "/sdc.jpg" },
    { name: "CSES Arcade", club: "CSE Society", imgsrc: "/cses.jpg" },
    { name: "No poster" },
  ];
  expect(orderEvents(events).map(e => e.name)).toEqual(["SDC Games", "CSES Arcade", "AI Unveiled", "Other", "No poster"]);
  expect(events[0].name).toBe("Other");
  expect(selectFeaturedEvents(events).map(e => e.name)).toEqual(["SDC Games", "CSES Arcade", "Other"]);
});

test("recognizes society name variants and keeps ordinary event ordering stable", () => {
  const events = [{ name: "Other 1" }, { name: "Other 2" }, { title: "Old CSE event", societyName: "Computer Science and Engineering Society" }];
  expect(orderEvents(events).map(e => e.name || e.title)).toEqual(["Old CSE event", "Other 1", "Other 2"]);
});

test("orders SDC Games, ARCADE, Smash Karts, CSE Society events, Venture Vortex, then the rest", () => {
  const events = [
    { name: "Other", imgsrc: "/other.jpg" },
    { name: "Venture Vortex", club: "Entrepreneurship Club", imgsrc: "/vv.jpg" },
    { name: "AI Unveiled", club: "CSE Society", imgsrc: "/ai.jpg" },
    { name: "CSES Arcade", club: "CSE Society", imgsrc: "/cses.jpg" },
    { name: "Smash Karts", club: "Robotics Club", imgsrc: "/smash.jpg" },
    { name: "ARCADE", club: "Robotics Club", imgsrc: "/arcade.jpg" },
    { name: "SDC Games", imgsrc: "/sdc.jpg" },
  ];
  const names = orderEvents(events).map(e => e.name);
  expect(names.slice(0, 3)).toEqual(["SDC Games", "ARCADE", "Smash Karts"]);
  expect(names.slice(3, 5).sort()).toEqual(["AI Unveiled", "CSES Arcade"]);
  expect(names.slice(5)).toEqual(["Venture Vortex", "Other"]);
});

test("bundled registration and catalogue data start with the pinned events", () => {
  const events = getFallbackEvents();
  expect(events.slice(0, 3).map(e => e.name)).toEqual(["SDC Games", "ARCADE", "Smash Karts"]);
  expect(events.slice(3, 5).every(e => e.club === "CSE Society")).toBe(true);
  expect(events[5].name).toBe("Venture Vortex");
});
