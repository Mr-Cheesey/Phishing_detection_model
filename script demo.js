// PHISHING URL DETECTOR ENGINE FUNCTIONS USAGE (SCRIPT NOT INCLUDED)



const suspiciousKeywords = [
"login","verify","secure","update","bank",
"account","signin","payment","confirm",
"password","wallet","billing","recover"
];

// sample URLs
const demoUrls = [
"https://google.com",
"https://github.com",
"http://secure-login-paypal-update.xyz",
"http://192.168.0.1/verify",
"http://banking-alert-confirm-user.info/login",
"https://microsoft.com"
];

let historyList=[];

// MAIN SCAN FUNCTION

function scanURL(){

let url=document.getElementById("urlInput").value.trim();

if(url==""){
alert("Enter URL first");
return;
}

// auto add https
if(!url.startsWith("http")){
url="https://"+url;
}

let risk=0;
let reasons=[];


// FEATURE EXTRACTION


// URL length
if(url.length>75){
risk+=15;
reasons.push("URL length unusually long");
}
else if(url.length>50){
risk+=8;
reasons.push("URL moderately long");
}

// special characters
let specialCount=(url.match(/[@_\-=]/g)||[]).length;

if(specialCount>=3){
risk+=12;
reasons.push("multiple special characters detected");
}
else if(specialCount>=1){
risk+=5;
reasons.push("special characters present");
}

// dot count
let dotCount=(url.match(/\./g)||[]).length;

if(dotCount>3){
risk+=10;
reasons.push("too many subdomains");
}

// https check
if(!url.startsWith("https")){
risk+=18;
reasons.push("HTTPS not used");
}

// IP address check
if(/\d+\.\d+\.\d+\.\d+/.test(url)){
risk+=25;
reasons.push("IP address used instead of domain");
}

// hyphen domain
if(url.includes("-")){
risk+=8;
reasons.push("hyphen detected in domain");
}

// keyword detection
let keywordHits=0;

suspiciousKeywords.forEach(word=>{
if(url.toLowerCase().includes(word)){
keywordHits++;
}
});

if(keywordHits>=3){
risk+=25;
reasons.push("multiple phishing keywords detected");
}
else if(keywordHits>=1){
risk+=12;
reasons.push("suspicious keyword detected");
}

// suspicious TLD
if(/\.(xyz|top|info|click|live|rest|buzz)/.test(url)){
risk+=10;
reasons.push("suspicious domain extension");
}


// NORMALIZE RISK


if(risk>100){
risk=100;
}


// CLASSIFICATION


let result="";
let color="";
let badgeClass="";

if(risk<35){

result="Safe Website";
color="green";
badgeClass="safe";

}
else if(risk<70){

result="Suspicious Website";
color="orange";
badgeClass="warn";

}
else{

result="Phishing Website";
color="red";
badgeClass="danger";

}


// UI UPDATE


// result text
document.getElementById("result").innerHTML=result;
document.getElementById("result").style.color=color;

// score
document.getElementById("riskScore").innerHTML="Risk Score: "+risk+"%";

// reasons
document.getElementById("reasonBox").innerHTML=reasons.join("<br>");

// progress bar
document.getElementById("riskBar").style.width=risk+"%";

// status badge
document.getElementById("statusBadge").className="badge "+badgeClass;
document.getElementById("statusBadge").innerHTML=result;

// add history
addHistory(url,result,risk);

// animate loading bar
animateBar(risk);

}


// PROGRESS ANIMATION


function animateBar(target){

let bar=document.getElementById("riskBar");

bar.style.width="0%";

let width=0;

let interval=setInterval(()=>{

if(width>=target){

clearInterval(interval);

}
else{

width++;

bar.style.width=width+"%";

}

},5);

}


// CLEAR INPUT


function clearInput(){

document.getElementById("urlInput").value="";

document.getElementById("result").innerHTML="Result will appear here";

document.getElementById("riskScore").innerHTML="";

document.getElementById("reasonBox").innerHTML="";

document.getElementById("riskBar").style.width="0%";

document.getElementById("statusBadge").className="badge";

}


// RANDOM DEMO URL


function randomURL(){

let random=demoUrls[Math.floor(Math.random()*demoUrls.length)];

document.getElementById("urlInput").value=random;

scanURL();

}


// HISTORY FUNCTION


function addHistory(url,result,score){

historyList.unshift({

url:url,
result:result,
score:score,
time:new Date().toLocaleTimeString()

});

if(historyList.length>5){

historyList.pop();

}

displayHistory();

}

// show history

function displayHistory(){

let html="";

historyList.forEach(item=>{

html+=`

<div class="historyItem">

<b>${item.result}</b>
<br>
${item.url}
<br>
Score: ${item.score}%
<br>
${item.time}

</div>

`;

});

document.getElementById("history").innerHTML=html;

}


// COPY REPORT


function copyReport(){

let report=document.getElementById("reasonBox").innerText;

navigator.clipboard.writeText(report);

alert("Report copied");

}


// ENTER KEY SUPPORT


document.getElementById("urlInput").addEventListener("keypress",function(e){

if(e.key==="Enter"){

scanURL();

}

});