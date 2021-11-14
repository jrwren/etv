"use strict";

const etv = document.getElementById("checkboxTV")
const statusTV = document.getElementById("statusTV")

const switchYT = document.getElementById("checkboxYT")
const statusYT = document.getElementById("statusYT")

const switchFB = document.getElementById("checkboxFB")
const statusFB = document.getElementById("statusFB")

const switchLilly = document.getElementById("checkboxLilly")
const statusLilly = document.getElementById("statusLilly")

const switchBeacons = document.getElementById("checkboxBeacons")
const statusBeacons = document.getElementById("statusBeacons")

const switchPorn = document.getElementById("checkboxPorn")
const statusPorn = document.getElementById("statusPorn")

const downloadToTVText = document.getElementById("downloadToTVText")
const downloadToTVButton = document.getElementById("downloadToTVButton")

const resH = document.getElementById("response")
const recenttv = document.getElementById("recenttv")
const recentmovies = document.getElementById("recentmovies")
const recentdns = document.getElementById("recentdns")

//make etv.onclick like below
etv.onclick = function () {
    hit("etv")
}

switchYT.onclick = () => dependOnCheck(switchYT, "YT")
switchFB.onclick = () => dependOnCheck(switchFB, "FB")
switchLilly.onclick = () => dependOnCheck(switchLilly, "Lilly")
switchBeacons.onclick = () => dependOnCheck(switchBeacons, "Beacons")
switchPorn.onclick = () => dependOnCheck(switchPorn, "Porn")

function dependOnCheck(inputElement, identifier) {
    // The logic here looks backwards because this executes AFTER
    // the state change.
    if (inputElement.checked) {
        hit("enable" + identifier)
        return
    }
    hit("block" + identifier)
}

const server = "http://delays.powerpuff:9620/"

function hit(path, body = undefined) {
    const postbody = body ?? { "nope": "nothing" }
    fetch(server + path, { "method": "POST", credentials: "include", "body": JSON.stringify(postbody) })
        .then(function (response) {
            if (!response.ok) {
                resH.firstChild.textContent = "there was an error enabling TV:" + response.status
                return
            }
            return response.json()
        }).then(data => {
            console.log(data)
            resH.firstChild.textContent = data.message ?? data.status
            updateYTStatus()
            updateFBStatus()
            updateLillyStatus()
            updateBeaconStatus()
            updatePornStatus()
            updateTVStatus()
        })
}

function updateYTStatus() {
    updateStatus("statusYT", statusYT, "Youtube", switchYT)
}

function updateFBStatus() {
    updateStatus("statusFB", statusFB, "Facebook", switchFB)
}

function updateLillyStatus() {
    updateStatus("statusLilly", statusLilly, "Lilly", switchLilly)
}

function updateBeaconStatus() {
    updateStatus("statusBeacons", statusBeacons, "Beacon", switchBeacons)
}

function updatePornStatus() {
    updateStatus("statusPorn", statusPorn, "Porn", switchPorn)
}

function updateTVStatus() {
    updateStatus("statusTV", statusTV, "TV", etv)
}

function updateStatus(endpoint, msgelement, msg, checkbox) {
    fetch(server + endpoint, { credentials: "include" }).then((resp) => {
        if (!resp.ok) {
            msgelement.firstChild.data = "could not fetch current " + msg + " status"
            return
        }
        return resp.json()
    }).then(data => {
        msgelement.firstChild.data = data.status
        if (data.status.includes("enabled")) {
            checkbox.checked = true
        }
        if (data?.loginstatus === "true") {
            document.getElementById("loginform").style.display = "none"
            document.getElementById("logoutform").firstElementChild.innerHTML = data?.username
            document.getElementById("logoutform").style.display = "block"
        }
        if (data?.tvpstatus) {
            document.getElementById("tvpstatus").innerHTML = data?.tvpstatus
        }
    }).catch(reason => { console.log(reason) })
}

downloadToTVButton.onclick = function () {
    if (downloadToTVText.textContent) {
        hit("download", { "target": "tv", "url": downloadToTVText.textContent })
    }
}

let updateList = function (list, element) {
    let ol = document.createElement("ol")
    for (var i = 0; i < list.length; i++) {
        if (list[i] == "") {
            continue
        }
        var li = document.createElement("li");
        li.innerHTML = list[i]
        li.setAttribute("class", "line")
        ol.appendChild(li)
    }
    element.appendChild(ol)
}
let getRecentTVAndMovies = function () {
    fetch(server + 'recent').then((resp) => {
        if (!resp.ok) {
            console.log("OH NO! ", resp)
        }
        return resp.json()
    }).then(data => {
        // loop through data.tv and data.movies and create ol with li
        updateList(data.tv, recenttv)
        updateList(data.movies, recentmovies)
        updateList(data.dns, recentdns)
    }).catch(reason => { console.log(reason) })
}

updateTVStatus()
updateYTStatus()
updateFBStatus()
updateLillyStatus()
updateBeaconStatus()
updatePornStatus()

getRecentTVAndMovies()
