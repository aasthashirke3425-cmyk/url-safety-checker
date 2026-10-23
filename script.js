const urlInput = document.getElementById("urlInput");
const scanButton = document.getElementById("scanButton");

const loading = document.getElementById("loading");
const resultSection = document.getElementById("resultSection");

const scoreElement = document.getElementById("score");
const riskLevel = document.getElementById("riskLevel");
const riskDescription = document.getElementById("riskDescription");

const riskBadge = document.getElementById("riskBadge");

const analyzedUrl = document.getElementById("analyzedUrl");

const checksList = document.getElementById("checksList");

const recommendationText =
    document.getElementById("recommendationText");

const historyList =
    document.getElementById("historyList");

const clearHistoryButton =
    document.getElementById("clearHistory");

const copyButton =
    document.getElementById("copyButton");

const newScanButton =
    document.getElementById("newScanButton");


/*
    Suspicious keywords commonly seen
    in phishing/social engineering URLs.
*/

const suspiciousKeywords = [
    "login",
    "verify",
    "verification",
    "password",
    "account",
    "secure",
    "security",
    "update",
    "confirm",
    "signin",
    "bank",
    "wallet",
    "payment",
    "recover",
    "unlock",
    "authenticate"
];


/*
    Main scanning function
*/

function scanURL() {

    const input = urlInput.value.trim();

    if (!input) {

        alert("Please enter a URL.");

        return;
    }


    /*
        Add https if the user forgot
        to enter a protocol.
    */

    let urlString = input;

    if (!/^https?:\/\//i.test(urlString)) {

        urlString = "https://" + urlString;

    }


    let url;

    try {

        url = new URL(urlString);

    } catch (error) {

        alert("Please enter a valid URL.");

        return;

    }


    /*
        Show loading animation.
    */

    resultSection.classList.add("hidden");

    loading.classList.remove("hidden");


    /*
        Small delay to make the scanner
        feel like a real security tool.
    */

    setTimeout(() => {

        const result = analyzeURL(url);

        displayResult(result);

        saveHistory({
            url: input,
            score: result.score,
            risk: result.risk
        });

        loading.classList.add("hidden");

        resultSection.classList.remove("hidden");

        resultSection.scrollIntoView({
            behavior: "smooth"
        });

    }, 700);

}


/*
    URL analysis
*/

function analyzeURL(url) {

    let score = 0;

    const checks = [];


    /*
        1. HTTPS
    */

    if (url.protocol === "https:") {

        checks.push({
            name: "HTTPS Encryption",
            description: "Connection uses HTTPS.",
            safe: true
        });

    } else {

        score += 20;

        checks.push({
            name: "HTTPS Encryption",
            description: "Connection does not use HTTPS.",
            safe: false
        });

    }


    /*
        2. IP address detection
    */

    const ipPattern =
        /^(?:\d{1,3}\.){3}\d{1,3}$/;

    if (ipPattern.test(url.hostname)) {

        score += 25;

        checks.push({
            name: "IP Address Domain",
            description: "URL uses an IP address instead of a normal domain.",
            safe: false
        });

    } else {

        checks.push({
            name: "IP Address Domain",
            description: "Normal domain name detected.",
            safe: true
        });

    }


    /*
        3. URL length
    */

    if (url.href.length > 150) {

        score += 15;

        checks.push({
            name: "URL Length",
            description: "URL is unusually long.",
            safe: false
        });

    } else {

        checks.push({
            name: "URL Length",
            description: "URL length appears normal.",
            safe: true
        });

    }


    /*
        4. @ symbol
    */

    if (url.href.includes("@")) {

        score += 20;

        checks.push({
            name: "Suspicious @ Symbol",
            description: "URL contains an @ symbol.",
            safe: false
        });

    } else {

        checks.push({
            name: "Suspicious @ Symbol",
            description: "No @ symbol detected.",
            safe: true
        });

    }


    /*
        5. Suspicious keywords
    */

    const lowerURL = url.href.toLowerCase();

    const foundKeywords =
        suspiciousKeywords.filter(keyword =>
            lowerURL.includes(keyword)
        );


    if (foundKeywords.length > 0) {

        score += Math.min(
            foundKeywords.length * 5,
            20
        );

        checks.push({
            name: "Suspicious Keywords",
            description:
                "Detected: " +
                foundKeywords.join(", "),
            safe: false
        });

    } else {

        checks.push({
            name: "Suspicious Keywords",
            description:
                "No common suspicious keywords detected.",
            safe: true
        });

    }


    /*
        6. Subdomains
    */

    const parts = url.hostname.split(".");

    const subdomainCount =
        Math.max(parts.length - 2, 0);


    if (subdomainCount >= 3) {

        score += 15;

        checks.push({
            name: "Subdomain Structure",
            description:
                "URL contains many subdomains.",
            safe: false
        });

    } else {

        checks.push({
            name: "Subdomain Structure",
            description:
                "Domain structure appears normal.",
            safe: true
        });

    }


    /*
        7. Hyphen count
    */

    const hyphenCount =
        (url.hostname.match(/-/g) || []).length;


    if (hyphenCount >= 3) {

        score += 10;

        checks.push({
            name: "Domain Hyphens",
            description:
                "Domain contains many hyphens.",
            safe: false
        });

    } else {

        checks.push({
            name: "Domain Hyphens",
            description:
                "Normal number of hyphens.",
            safe: true
        });

    }


    /*
        8. Encoded characters
    */

    if (/%[0-9a-f]{2}/i.test(url.href)) {

        score += 5;

        checks.push({
            name: "Encoded Characters",
            description:
                "URL contains encoded characters.",
            safe: false
        });

    } else {

        checks.push({
            name: "Encoded Characters",
            description:
                "No unusual encoded characters detected.",
            safe: true
        });

    }


    /*
        Keep score between 0 and 100.
    */

    score = Math.min(score, 100);


    /*
        Determine risk.
    */

    let risk;

    if (score <= 25) {

        risk = "LOW";

    } else if (score <= 55) {

        risk = "MEDIUM";

    } else {

        risk = "HIGH";

    }


    return {
        score,
        risk,
        checks
    };

}


/*
    Display result
*/

function displayResult(result) {

    scoreElement.textContent = result.score;

    analyzedUrl.textContent =
        urlInput.value;


    /*
        Risk information
    */

    if (result.risk === "LOW") {

        riskLevel.textContent = "Low Risk";

        riskDescription.textContent =
            "The URL does not show many suspicious characteristics.";

        riskBadge.textContent =
            "🟢 LOW RISK";

        riskBadge.style.background =
            "rgba(72,229,160,0.12)";

        riskBadge.style.color =
            "#48e5a0";

        recommendationText.textContent =
            "The URL appears relatively normal, but always verify the website before entering sensitive information.";

    }


    else if (result.risk === "MEDIUM") {

        riskLevel.textContent = "Medium Risk";

        riskDescription.textContent =
            "Some suspicious characteristics were detected.";

        riskBadge.textContent =
            "🟡 MEDIUM RISK";

        riskBadge.style.background =
            "rgba(229,185,72,0.12)";

        riskBadge.style.color =
            "#e5b948";

        recommendationText.textContent =
            "Be cautious. Verify the domain through an official source before entering passwords or financial information.";

    }


    else {

        riskLevel.textContent = "High Risk";

        riskDescription.textContent =
            "Multiple suspicious URL characteristics were detected.";

        riskBadge.textContent =
            "🔴 HIGH RISK";

        riskBadge.style.background =
            "rgba(255,107,107,0.12)";

        riskBadge.style.color =
            "#ff6b6b";

        recommendationText.textContent =
            "Avoid opening this URL or entering sensitive information unless you can independently verify the website.";

    }


    /*
        Score circle
    */

    if (result.risk === "LOW") {

        document.querySelector(".score-circle").style.borderColor =
            "#48e5a0";

    }

    else if (result.risk === "MEDIUM") {

        document.querySelector(".score-circle").style.borderColor =
            "#e5b948";

    }

    else {

        document.querySelector(".score-circle").style.borderColor =
            "#ff6b6b";

    }


    /*
        Security checks
    */

    checksList.innerHTML = "";


    result.checks.forEach(check => {

        const item =
            document.createElement("div");

        item.className =
            "check-item";


        const icon =
            check.safe ? "✓" : "⚠";


        const status =
            check.safe ? "PASS" : "WARNING";


        item.innerHTML = `

            <div class="check-info">

                <div class="check-icon">
                    ${icon}
                </div>

                <div class="check-text">

                    <strong>
                        ${check.name}
                    </strong>

                    <span>
                        ${check.description}
                    </span>

                </div>

            </div>

            <div class="check-status">
                ${status}
            </div>

        `;


        checksList.appendChild(item);

    });

}


/*
    Save scan history
*/

function saveHistory(data) {

    let history =
        JSON.parse(
            localStorage.getItem("urlHistory")
        ) || [];


    history.unshift(data);


    /*
        Keep only latest 10 scans.
    */

    history =
        history.slice(0, 10);


    localStorage.setItem(
        "urlHistory",
        JSON.stringify(history)
    );


    displayHistory();

}


/*
    Display scan history
*/

function displayHistory() {

    let history =
        JSON.parse(
            localStorage.getItem("urlHistory")
        ) || [];


    if (history.length === 0) {

        historyList.innerHTML = `
            <p class="empty-history">
                No URLs scanned yet.
            </p>
        `;

        return;

    }


    historyList.innerHTML = "";


    history.forEach(item => {

        const element =
            document.createElement("div");

        element.className =
            "history-item";


        let symbol;

        if (item.risk === "LOW") {

            symbol = "🟢";

        } else if (item.risk === "MEDIUM") {

            symbol = "🟡";

        } else {

            symbol = "🔴";

        }


        element.innerHTML = `

            <div class="history-url">
                ${symbol} ${escapeHTML(item.url)}
            </div>

            <div class="history-risk">
                ${item.score}/100
                ${item.risk}
            </div>

        `;


        historyList.appendChild(element);

    });

}


/*
    Prevent HTML injection in history.
*/

function escapeHTML(text) {

    const div =
        document.createElement("div");

    div.textContent = text;

    return div.innerHTML;

}


/*
    Clear history
*/

clearHistoryButton.addEventListener(
    "click",
    () => {

        localStorage.removeItem(
            "urlHistory"
        );

        displayHistory();

    }
);


/*
    Scan button
*/

scanButton.addEventListener(
    "click",
    scanURL
);


/*
    Press Enter to scan
*/

urlInput.addEventListener(
    "keydown",
    event => {

        if (event.key === "Enter") {

            scanURL();

        }

    }
);


/*
    New scan
*/

newScanButton.addEventListener(
    "click",
    () => {

        urlInput.value = "";

        resultSection.classList.add(
            "hidden"
        );

        urlInput.focus();

        window.scrollTo({
            top: 0,
            behavior: "smooth"
        });

    }
);


/*
    Copy result
*/

copyButton.addEventListener(
    "click",
    async () => {

        const text =
            `
URL Sentinel Analysis

URL:
${urlInput.value}

Risk:
${riskLevel.textContent}

Score:
${scoreElement.textContent}/100
            `;


        try {

            await navigator.clipboard.writeText(text);

            copyButton.textContent =
                "✓ Copied!";

            setTimeout(() => {

                copyButton.textContent =
                    "📋 Copy Result";

            }, 1500);

        } catch (error) {

            alert(
                "Unable to copy result."
            );

        }

    }
);


/*
    Load previous history
*/

displayHistory();