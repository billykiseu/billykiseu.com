//copyright Kiseu//

//Preloader
var loader = document.getElementById("preloader");
window.addEventListener("load", function () {
  loader.style.display = "none";
});

//Search-toggle-full
const icon1 = document.getElementById("search-icon-full");
const navtoggle = document.getElementById("nav-bar-full");
const search = document.getElementById("search-full");
const cancel = document.getElementById("close-full");

icon1.addEventListener("click", () => {
  search.classList.toggle("active");
  navtoggle.classList.toggle("active");
});
cancel.addEventListener("click", () => {
  search.classList.toggle("active");
  navtoggle.classList.toggle("active");
});

//Menuactive
var btnContainer = document.getElementById("highlight");
var btns = btnContainer.getElementsByClassName("btn");

for (var i = 0; i < btns.length; i++) {
  btns[i].addEventListener("click", function () {
    var current = document.getElementsByClassName("highlight");
    current[0].className = current[0].className.replace("highlight");
    this.className += " highlight";
  });
}

//Search-toggle-mobile
const icon1m = document.getElementById("search-icon-mobile");
const navtogglem = document.getElementById("nav-bar-mobile");
const searchm = document.getElementById("search-mobile");
const cancelm = document.getElementById("close-mobile");

icon1m.addEventListener("click", () => {
  searchm.classList.toggle("active");
  navtogglem.classList.toggle("active");
});
cancelm.addEventListener("click", () => {
  searchm.classList.toggle("active");
  navtogglem.classList.toggle("active");
});

//Menu-toggle
const menutoggle = document.getElementById("menu-toggle");
const menuclose = document.getElementById("menu-close");
const navmobile = document.getElementById("nav-mobile");

menutoggle.addEventListener("click", () => {
  navmobile.classList.toggle("active");
});
menuclose.addEventListener("click", () => {
  navmobile.classList.toggle("active");
});

//Hide-show navbar
let lastScroll = 0;
const target = document.getElementById("peek");

window.addEventListener("scroll", () => {
  const currentScroll = window.pageYOffset;

  //nav-darkmode-flip
  const codedark = document.getElementById("codeid");
  const digitalartdark = document.getElementById("digitalartid");
  const musicdark = document.getElementById("musicid");
  const exploredark = document.getElementById("exploreid");
  const codedicon = document.getElementById("codeicon");
  const digitalarticon = document.getElementById("digitalarticon");
  const musicicon = document.getElementById("musicicon");
  const exploreicon = document.getElementById("musicicon");
  const searchcloseicon = document.getElementById("close-full");
  const searchgoicon = document.getElementById("go-icon");
  const searchcloseiconm = document.getElementById("close-mobile");
  const searchgoiconm = document.getElementById("go-mobile");
  const cartflip = document.getElementById("cartflip");

  if (currentScroll <= 100) {
    target.style.backgroundImage = "none";
    icon1.classList.add("dark");
    icon1m.classList.add("dark");
    menutoggle.classList.add("dark");
    codedark.style.color = "var(--white)";
    digitalartdark.style.color = "var(--white)";
    musicdark.style.color = "var(--white)";
    exploredark.style.color = "var(--white)";
    codedicon.style.filter = "invert(100)";
    digitalarticon.style.filter = "invert(100)";
    musicicon.style.filter = "invert(100)";
    exploreicon.style.filter = "invert(100)";
    searchgoicon.style.filter = "invert(100)";
    searchcloseiconm.style.filter = "invert(100)";
    searchgoiconm.style.filter = "invert(100)";
    searchcloseicon.style.filter = "invert(100)";
    cartflip.style.filter = "invert(100)";
  }
  if (currentScroll > 100) {
    target.style.backgroundImage = 'url("/static/assets/bg3.jpg")';
    icon1.classList.remove("dark");
    icon1m.classList.remove("dark");
    menutoggle.classList.remove("dark");
    codedark.style.color = "var(--black)";
    digitalartdark.style.color = "var(--black)";
    musicdark.style.color = "var(--black)";
    exploredark.style.color = "var(--black)";
    codedicon.style.filter = "invert(0)";
    digitalarticon.style.filter = "invert(0)";
    musicicon.style.filter = "invert(0)";
    exploreicon.style.filter = "invert(0)";
    searchgoicon.style.filter = "invert(0)";
    searchcloseicon.style.filter = "invert(0)";
    searchgoiconm.style.filter = "invert(0)";
    searchcloseiconm.style.filter = "invert(0)";
    cartflip.style.filter = "invert(0)";
  }
  if (currentScroll > lastScroll && !target.classList.contains("hide")) {
    target.classList.remove("show");
    target.classList.add("hide");
  }
  if (currentScroll < lastScroll && !target.classList.contains("show")) {
    target.classList.remove("hide");
    target.classList.add("show");
  }

  lastScroll = currentScroll;
});

//Scroll-to-top
mybutton = document.getElementById("up");
window.onscroll = function () {
  scrollFunction();
};
function scrollFunction() {
  if (document.body.scrollTop > 20 || document.documentElement.scrollTop > 20) {
    mybutton.style.display = "block";
  } else {
    mybutton.style.display = "none";
  }
}
function topFunction() {
  document.body.scrollTop = 0; // For Safari
  document.documentElement.scrollTop = 0;
}

//Contact-scroll
const contactscroll = document.getElementById("contact-trigger");
const contactscrollmobi = document.getElementById("contact-trigger2");
const footerloc = document.getElementById("contactloc");

contactscroll.addEventListener("click", () => {
  footerloc.scrollIntoView();
});
contactscrollmobi.addEventListener("click", () => {
  footerloc.scrollIntoView();
});

//Cookie-consent
const cookieModal = document.querySelector(".cookies-super");
const cancelcookie = document.getElementById("cancelcookies");
const acceptcookie = document.getElementById("acceptall");

cancelcookie.addEventListener("click", function () {
  //alert("message");
  cookieModal.classList.remove("active");
});
acceptcookie.addEventListener("click", function () {
  cookieModal.classList.remove("active");
  localStorage.setItem("cookieAccepted", "yes");
});

setTimeout(function () {
  let cookieAccepted = localStorage.getItem("cookieAccepted");
  if (cookieAccepted != "yes") {
    cookieModal.classList.add("active");
  }
}, 4000);
