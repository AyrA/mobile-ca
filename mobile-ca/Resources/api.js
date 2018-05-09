"use strict";

var config = null;

function getCertsOfCA(hash) {
    var ret = [];
    $("#cert tbody [data-content]").each(function () {
        var cert = $(this).data("content");
        if (cert.issuer === hash) {
            ret.push(cert);
        }
    });
    return ret;
}

function getIdFromPubkey(pubkey) {
    var id = null;
    $("#keys tbody [data-content]").each(function () {
        var key = $(this).data("content");
        if (key.pubkey === pubkey) {
            id = key.id;
        }
    });
    return id;
}

function getCertsForPubkey(pubkey) {
    var certList = { ca: [], cert: [] };
    $("#ca tbody [data-content]").each(function (v) {
        var cert = $(this).data("content");
        if (cert.pubkey === pubkey) {
            certList.ca.push(cert.hash);
        }
    });
    $("#cert tbody [data-content]").each(function (v) {
        var cert = $(this).data("content");
        if (cert.pubkey === pubkey) {
            certList.cert.push(cert.hash);
        }
    });
    return certList;
}

function showCert(cert) {
    console.log(cert);
    var parent = $("#CA-" + cert.issuer).data("content");
    if (parent) {
        $("#certParent").val(parent.name);
    }
    $("#certValidFrom").val(toDate(cert.start));
    $("#certValidTo").val(toDate(cert.end));
    $("#certRsaKeyId").val(getIdFromPubkey(cert.pubkey) || "Unknown private key");
    $("#certDomain").val(cert.domain);
    $("#certDetailId").val(cert.hash);
    $("#certDetailName").val(cert.name);
    $("#certDetailData").val(cert.data)
    $("#certDomainList").html("<option></option>");
    $("#certDomainList option").val(cert.domain);
    $("#certDomainList option").text(cert.domain);
    $("#certDomainList").attr("size", (cert.san || []).length + 1);
    if (cert.san) {
        for (var i = 0; i < cert.san.length; i++) {
            var opt = document.createElement("option");
            opt.textContent = opt.value = cert.san[i];
            document.querySelector("#certDomainList").appendChild(opt);
        }

    }
    $("#modCertDetails").data("cert", cert);
    $("#modCertDetails").modal("show");
}
function removeCert(id) {
    $("#CERT-" + id).remove();
}

function addCert(cert) {
    var row = document.createElement("tr");
    row.setAttribute("data-content", JSON.stringify(cert));
    row.id = "CERT-" + cert.hash;
    //Hash
    var hash = document.createElement("td");
    hash.textContent = cert.hash;
    row.appendChild(hash);
    //Content
    var content = document.createElement("td");
    content.textContent = [cert.domain].concat(cert.san || []).join(", ");
    row.appendChild(content);
    //Blank
    row.appendChild(document.createElement("td"));
    //Add Row
    document.querySelector("#cert tbody").appendChild(row);
    //Add Event
    row.addEventListener("click", function () {
        var data = $(this).data("content");
        if (data) {
            showCert(data);
        }
    });
}
function genCert(data) {
    var req = new XMLHttpRequest();
    req.onload = function () {
        var data = JSON.parse(req.responseText);
        if (data.success) {
            addCert(data.data);
            showCert(data.data);
        }
        else {
            doAlert("Problem generating certificate", data.data, location.reload.bind(location));
        }
    };
    req.onerror = reqError;
    req.open("post", "/gencert", true);
    req.send(JSON.stringify(data));
}
function getCert() {
    var req = new XMLHttpRequest();
    req.onload = function () {
        var data = JSON.parse(req.responseText);
        if (data.success) {
            $("#cert tbody").html("");
            for (var i = 0; i < data.data.length; i++) {
                addCert(data.data[i]);
            }
        }
        else {
            doAlert("Problem loading certificates", data.data, location.reload.bind(location));
        }
    };
    req.onerror = reqError;
    req.open("get", "/getcert", true);
    req.send();
}
function delCert(id) {
    var req = new XMLHttpRequest();
    req.onload = function () {
        var data = JSON.parse(req.responseText);
        if (data.success) {
            removeCert(data.data);
        }
        else {
            doAlert("Problem deleting Certificate", data.data);
        }
    };
    req.onerror = reqError;
    req.open("post", "/delcert", true);
    req.send(JSON.stringify({ id: id }));
}


function showCA(cert) {
    $("#caValidFrom").val(toDate(cert.start));
    $("#caValidTo").val(toDate(cert.end));
    $("#caRsaKeyId").val(getIdFromPubkey(cert.pubkey) || "Unknown private key");
    $("#caDetailId").val(cert.hash);
    $("#caDetailName").val(cert.name);
    $("#caDetailData").val(cert.data);
    $("#modCADetails").data("ca", cert);
    $("#modCADetails").modal("show");
}
function removeCA(id) {
    $("#CA-" + id).remove();
}

function addCA(cert) {
    var row = document.createElement("tr");
    row.setAttribute("data-content", JSON.stringify(cert));
    row.id = "CA-" + cert.hash;
    //Hash
    var hash = document.createElement("td");
    hash.textContent = cert.hash;
    row.appendChild(hash);
    //Content
    var content = document.createElement("td");
    content.textContent = cert.name;
    row.appendChild(content);
    //Blank
    row.appendChild(document.createElement("td"));
    //Add Row
    document.querySelector("#ca tbody").appendChild(row);
    //Add Event
    row.addEventListener("click", function () {
        var data = $(this).data("content");
        if (data) {
            showCA(data);
        }
    });
}
function genCA(data) {
    var req = new XMLHttpRequest();
    req.onload = function () {
        var data = JSON.parse(req.responseText);
        if (data.success) {
            addCA(data.data);
            showCA(data.data);
        }
        else {
            doAlert("Problem generating CA certificate", data.data, location.reload.bind(location));
        }
    };
    req.onerror = reqError;
    req.open("post", "/genca", true);
    req.send(JSON.stringify(data));
}
function getCA() {
    var req = new XMLHttpRequest();
    req.onload = function () {
        var data = JSON.parse(req.responseText);
        if (data.success) {
            $("#ca tbody").html("");
            for (var i = 0; i < data.data.length; i++) {
                addCA(data.data[i]);
            }
        }
        else {
            doAlert("Problem loading CA certificates", data.data, location.reload.bind(location));
        }
    };
    req.onerror = reqError;
    req.open("get", "/getca", true);
    req.send();
}
function delCA(id) {
    var req = new XMLHttpRequest();
    req.onload = function () {
        var data = JSON.parse(req.responseText);
        if (data.success) {
            removeCA(data.data);
        }
        else {
            doAlert("Problem deleting CA Certificate", data.data);
        }
    };
    req.onerror = reqError;
    req.open("post", "/delca", true);
    req.send(JSON.stringify({ id: id }));
}


function showKey(key) {
    var certs = getCertsForPubkey(key.pubkey);
    $("#selKeyCAList").html("");
    $("#selKeyCertList").html("");
    document.querySelector("#selKeyCAList").size = Math.max(certs.ca.length, 1);
    document.querySelector("#selKeyCertList").size = Math.max(certs.cert.length, 1);
    for (var i = 0; i < certs.ca.length; i++) {
        var oca = document.createElement("option");
        oca.value = certs.ca[i];
        oca.textContent = oca.value.substr(0, 20);
        document.querySelector("#selKeyCAList").appendChild(oca);
    }
    for (var j = 0; j < certs.cert.length; j++) {
        var ocert = document.createElement("option");
        ocert.textContent = ocert.value = certs.cert[j];
        ocert.textContent = ocert.value.substr(0, 20);
        document.querySelector("#selKeyCertList").appendChild(ocert);
    }
    $("#modKeyDetails [type=text]").val(key.id);
    $("#modKeyDetails .pubkey").val(key.pubkey);
    $("#modKeyDetails .privkey").val(key.key);
    $("#modKeyDetails").data("key", key);
    $("#modKeyDetails").modal("show");
}
function removeKey(id) {
    $("#RSA-" + id).remove();
}

function delKey(id) {
    var req = new XMLHttpRequest();
    req.onload = function () {
        var data = JSON.parse(req.responseText);
        if (data.success) {
            removeKey(data.data);
        }
        else {
            doAlert("Problem deleting RSA Key", data.data);
        }
    };
    req.onerror = reqError;
    req.open("post", "/delkey", true);
    req.send(JSON.stringify({ id: id }));
}
function addKey(key) {
    var row = document.createElement("tr");
    row.setAttribute("data-content", JSON.stringify(key));
    row.id = "RSA-" + key.id;
    //Hash
    var id = document.createElement("td");
    id.textContent = key.id;
    row.appendChild(id);
    //Content
    var content = document.createElement("td");
    content.textContent = key.key.substr(key.key.indexOf('\n'), 20) + "..." + key.key.substr(key.key.lastIndexOf('\n') - 20, 20);
    row.appendChild(content);
    //Blank
    row.appendChild(document.createElement("td"));
    //Add Row
    document.querySelector("#keys tbody").appendChild(row);
    //Add Event
    row.addEventListener("click", function () {
        var data = $(this).data("content");
        if (data) {
            showKey(data);
        }
    });
}
function genKey(size) {
    var req = new XMLHttpRequest();
    req.onload = function () {
        var data = JSON.parse(req.responseText);
        if (data.success) {
            showKey(data.data);
            addKey(data.data);
        }
        else {
            doAlert("Problem generating RSA Key", data.data);
        }
    };
    req.onerror = reqError;
    req.open("post", "/genkey", true);
    req.send(JSON.stringify({ keySize: size }));
}
function getKeys() {
    var req = new XMLHttpRequest();
    req.onload = function () {
        var data = JSON.parse(req.responseText);
        if (data.success) {
            $("#keys tbody").html("");
            for (var i = 0; i < data.data.length; i++) {
                addKey(data.data[i]);
            }
        }
        else {
            doAlert("Problem loading keys", data.data, location.reload.bind(location));
        }
    };
    req.onerror = reqError;
    req.open("get", "/getkeys", true);
    req.send();
}

function getPfx(hash, keyId, pw, cb) {

    var post = {
        password: pw || "",
        cert: "",
        key: "",
        parents: []
    };

    //Try for Root CA first
    var data = $("#CA-" + hash).data("content");
    var key = $("#RSA-" + keyId).data("content");
    if (data && key) {
        post.cert = data.data;
        post.key = key.key;
        var req = new XMLHttpRequest();
        req.open("post", "/pfx", true);
        req.onload = function () {
            var answer = JSON.parse(req.responseText);
            cb(answer.success ? answer.data : null);
        };
        req.onerror = reqError;
        req.send(JSON.stringify(post));
    }
    else if (data) {
        doAlert("PFX Generator", "Can't find Private key with id " + keyId, cb);
    }
    else if (key) {
        //Try for regular certificate
        data = $("#CERT-" + hash).data("content");
        if (data) {
            var root = $("#CA-" + data.issuer).data("content");
            post.cert = data.data;
            post.key = key.key;
            if (root) {
                post.parents.push(root.data);
            }
            var req = new XMLHttpRequest();
            req.open("post", "/pfx", true);
            req.onload = function () {
                var answer = JSON.parse(req.responseText);
                cb(answer.success ? answer.data : null);
            };
            req.onerror = reqError;
            req.send(JSON.stringify(post));
        }
        else {
            doAlert("PFX Generator", "Can't find Certificate with hash " + hash, cb);
        }
    }
    else {
        doAlert("PFX Generator", "Can't find specified Certificate and key", cb);
    }
}

function loadConfig(cb) {
    if (!config) {
        console.log("Loading configuration");
        var req = new XMLHttpRequest();
        req.onload = function () {
            var data = JSON.parse(req.responseText);
            if (data.success) {
                $("th button").removeAttr("disabled");
                config = data.data;
                for (var i = 0; i < config.sizes.length; i++) {
                    var opt = document.createElement("option");
                    opt.value = config.sizes[i];
                    opt.textContent = opt.value;
                    document.querySelector("#modKeyGen select").appendChild(opt);
                }
                if (cb) {
                    cb();
                }
            }
            else {
                doAlert("Problem loading Configuration", data.data, location.reload.bind(location));
            }
        };
        req.onerror = reqError;
        req.open("get", "/config", true);
        req.send();
    }
}

function reqError(e) {
    doAlert("Error making request", "There was an error making the request. Please ensure the server is still running and try again.");
}

function doAlert(title, text, cb) {
    //If text is a function the title wasn't given
    if (typeof text === typeof doAlert) {
        cb = text;
        text = title;
        title = document.title;
    }

    $("#modAlert").data("cb", cb);
    $("#modAlert .modal-title").text(title);
    $("#modAlert .modal-body").text(text);
    $("#modAlert").modal("show");
}
function doPrompt(title, query, value, isSecret, cb) {
    $("#modPrompt").data("cb", cb);
    $("#modPrompt .modal-title").text(title);
    $("#modPrompt .modal-body label").text(query);
    $("#modPrompt .modal-body input").attr("type", isSecret ? "password" : "text");
    $("#modPrompt .modal-body input").val(value ? value + "" : "");
    $("#modPrompt").modal("show");
}
function doConfirm(title, text, cb) {

    //If text is a function the title wasn't given
    if (typeof text === typeof doConfirm) {
        cb = text;
        text = title;
        title = "Confirm this action";
    }

    $("#modConfirm").data("cb", cb);
    $("#modConfirm .modal-title").text(title);
    $("#modConfirm .modal-body").text(text);
    $("#modConfirm").modal("show");
}

function showLic(requireConfirm) {
    $("#modLicense .btn-success")[!requireConfirm ? "hide" : "show"]();
    $("#modLicense .btn-danger")[!requireConfirm ? "hide" : "show"]();
    $("#modLicense .btn-secondary")[requireConfirm ? "hide" : "show"]();
    $("#modLicense").modal("show");
}

function toDate(jsonDate) {
    var d = new Date(jsonDate);
    return d.toLocaleDateString() + " " + d.toLocaleTimeString();
}

document.addEventListener("DOMContentLoaded", function () {
    var init = function () {
        loadConfig(function () {
            getKeys();
            getCA();
            getCert();
        });

        $("#btnHelp").on("click", function () { $("#modHelp").modal("show"); });

        $("#btnNewCert").on("click", function () {
            document.querySelector("#modCertGen form").reset();
            document.querySelector("#certKeyId").innerHTML = "";
            document.querySelector("#certRoot").innerHTML = "";
            $("#keys tbody [data-content]").each(function () {
                var key = $(this).data("content");
                var opt = document.createElement("option");
                var certs = getCertsForPubkey(key.pubkey);
                var certCount = certs.ca.length + certs.cert.length;
                opt.value = key.id;
                opt.textContent = key.id.substr(0, 13) + " (Used " + certCount + " time" + (certCount == 1 ? "" : "s") + ")";
                document.querySelector("#certKeyId").appendChild(opt);
            });
            $("#ca tbody [data-content]").each(function () {
                var cert = $(this).data("content");
                var opt = document.createElement("option");
                var certCount = getCertsOfCA(cert.hash).length;
                opt.value = cert.hash;
                opt.textContent = cert.hash.substr(0, 20) + " (Has " + certCount + " child" + (certCount == 1 ? "" : "ren") + ")";
                document.querySelector("#certRoot").appendChild(opt);
            });
            if ($("#certKeyId option").length > 0) {
                if ($("#certRoot option").length > 0) {
                    $("#modCertGen").modal("show");
                }
                else {
                    doConfirm("No Root certificate", "You need to generate at least one root certificate first. Do this now?", function (y) {
                        if (y) {
                            $("#modCAGen").modal("show");
                        }
                    });
                }
            }
            else {
                doConfirm("No RSA key", "You need to generate at least one private key first. Do this now?", function (y) {
                    if (y) {
                        $("#modKeyGen").modal("show");
                    }
                });
            }
        });

        $("#btnCertGen").on("click", function () {
            if (document.querySelector("#modCertGen form").reportValidity()) {
                var data = {
                    parent: $("#certRoot").val(),
                    id: $("#certKeyId").val(),
                    cc: $("#certCC").val(),
                    st: $("#certST").val(),
                    l: $("#certL").val(),
                    ou: $("#certOU").val(),
                    o: $("#certO").val(),
                    cn: $("#certCN").val(),
                    e: $("#certE").val(),
                    exp: +$("#certEXP").val(),
                    sha256: document.querySelector("#certSHA256").checked,
                    san: $("#certAdditional").val().trim().split('\n').filter(function (v) { return v.trim() !== "" })
                };
                $("#modCertGen").modal("hide");
                genCert(data);
            }
        });

        $("#btnNewCA").on("click", function () {
            document.querySelector("#modCAGen form").reset();
            document.querySelector("#modCAGen select").innerHTML = "";
            $("#keys tbody [data-content]").each(function () {
                var key = $(this).data("content");
                var opt = document.createElement("option");
                var certs = getCertsForPubkey(key.pubkey);
                var certCount = certs.ca.length + certs.cert.length;
                opt.value = key.id;
                opt.textContent = key.id.substr(0, 13) + " (Used " + certCount + " time" + (certCount == 1 ? "" : "s") + ")";
                document.querySelector("#modCAGen select").appendChild(opt);
            });
            if ($("#caKeyId option").length > 0) {
                $("#modCAGen").modal("show");
            }
            else {
                doConfirm("No RSA key", "You need to generate at least one private key first. Do this now?", function (y) {
                    if (y) {
                        $("#modKeyGen").modal("show");
                    }
                });
            }
        });

        $("#btnCAGen").on("click", function () {
            if (document.querySelector("#modCAGen form").reportValidity()) {
                var data = {
                    id: $("#caKeyId").val(),
                    cc: $("#caCC").val(),
                    st: $("#caST").val(),
                    l: $("#caL").val(),
                    ou: $("#caOU").val(),
                    o: $("#caO").val(),
                    cn: $("#caCN").val(),
                    e: $("#caE").val(),
                    exp: +$("#caEXP").val(),
                    sha256: document.querySelector("#caSHA256").checked
                };
                $("#modCAGen").modal("hide");
                genCA(data);
            }
        });

        $("#btnCADelete").on("click", function () {
            var cert = $("#modCADetails").data("ca");
            $("#modCADetails").modal("hide");
            doConfirm("Confirm irreversible action", "Delete this root certificate?", function (y) {
                if (y) {
                    delCA(cert.hash);
                }
                else {
                    $("#modCADetails").modal("show");
                }
            });
        });

        $("#btnCADownloadPub").on("click", function () {
            var data = "data:application/x-x509-ca-cert;base64," + btoa($("#caDetailData").val());
            var a = document.createElement("a");
            a.download = $("#caDetailId").val() + ".ca.crt";
            a.href = data;
            a.click();
        });

        $("#btnCADownloadPriv").on("click", function () {
            $("#modCADetails").modal("hide");
            doPrompt("PFX Export password", "PFX files are usually password protected. You can enter a password if you want", "", true, function (v) {
                $("#modCADetails").modal("show");
                if (v !== null) {
                    getPfx($("#caDetailId").val(), $("#caRsaKeyId").val(), v ? v : "", function (data) {
                        $("#modCADetails").modal("hide");
                        if (data) {
                            var pfx = "data:application/x-pkcs12;base64," + data;
                            var a = document.createElement("a");
                            a.download = $("#caDetailId").val() + ".pfx";
                            a.href = pfx;
                            a.click();
                        }
                        else {
                            doAlert("PFX Export", "Unable to generate PFX file", function () {
                                $("#modCADetails").modal("show");
                            });
                        }
                    });
                }
            });
        });


        $("#btnCertDelete").on("click", function () {
            var cert = $("#modCertDetails").data("cert");
            $("#modCertDetails").modal("hide");
            doConfirm("Confirm irreversible action", "Delete this certificate?", function (y) {
                if (y) {
                    delCert(cert.hash);
                }
                else {
                    $("#modCertDetails").modal("show");
                }
            });
        });

        $("#btnCertDownloadPub").on("click", function () {
            var data = "data:application/x-x509-ca-cert;base64," + btoa($("#certDetailData").val());
            var a = document.createElement("a");
            a.download = $("#certDetailId").val() + ".cli.crt";
            a.href = data;
            a.click();
        });

        $("#btnCertDownloadPriv").on("click", function () {
            $("#modCertDetails").modal("hide");
            doPrompt("PFX Export password", "PFX files are usually password protected. You can enter a password if you want", "", true, function (v) {
                if (v !== null) {
                    getPfx($("#certDetailId").val(), $("#certRsaKeyId").val(), v ? v : "", function (data) {
                        if (data) {
                            $("#modCertDetails").modal("show");
                            var pfx = "data:application/x-pkcs12;base64," + data;
                            var a = document.createElement("a");
                            a.download = $("#certDetailId").val() + ".pfx";
                            a.href = pfx;
                            a.click();
                        }
                        else {
                            doAlert("PFX Export", "Unable to generate PFX file", function () {
                                $("#modCertDetails").modal("show");
                            });
                        }
                    });
                }
                else {
                    $("#modCertDetails").modal("show");
                }
            });
        });


        $("#btnKeyDownload").on("click", function () {
            var data = "data:text/plain;base64," + btoa($("#modKeyDetails .privkey").val());
            var a = document.createElement("a");
            a.download = $("#modKeyDetails [type=text]").val() + ".rsa";
            a.href = data;
            a.click();
        });

        $("#btnNewKey").on("click", function () {
            $("#modKeyGen").modal("show");
        });
        $("#btnKeyGen").on("click", function () {
            $("#modKeyGen").modal("hide");
            genKey(document.querySelector("#modKeyGen select").value);
        });

        $("#btnKeyDelete").on("click", function () {
            var key = $("#modKeyDetails").data("key");
            var certs = getCertsForPubkey(key.pubkey);
            var count = certs.ca.length + certs.cert.length;
            $("#modKeyDetails").modal("hide");
            doConfirm("Confirm irreversible action", "Delete key " + key.id + "? This will render " + count + " certificate" + (count === 1 ? "" : "s") + " mostly useless.", function (y) {
                if (y) {
                    delKey(key.id);
                }
                else {
                    $("#modKeyDetails").modal("show");
                }
            });
        });

        $("#modAlert").on("hidden.bs.modal", function () {
            var cb = $("#modAlert").data("cb");
            $("#modAlert").data("cb", null);
            if (cb) {
                cb();
            }
        });

        $("#modConfirm").on("hidden.bs.modal", function () {
            var cb = $("#modConfirm").data("cb");
            var result = $("#modConfirm").data("result");
            $("#modConfirm").data("cb", null);
            $("#modConfirm").data("result", null);
            if (cb) {
                cb(result);
            }
        });

        $("#modPrompt").on("hidden.bs.modal", function () {
            var cb = $("#modPrompt").data("cb");
            var result = $("#modPrompt").data("result");
            $("#modPrompt").data("cb", null);
            $("#modPrompt").data("result", null);
            if (cb) {
                cb(result);
            }
        });

        $("#btnPromptOk").on("click", function () {
            $("#modPrompt").data("result", $("$modPrompt .modal-body input").val());
            $("#modPrompt").modal("hide");
        });
        $("#btnPromptCancel").on("click", function () {
            $("#modPrompt").data("result", null);
            $("#modPrompt").modal("hide");
        });

        $("#btnConfirmYes").on("click", function () {
            $("#modConfirm").data("result", true);
            $("#modConfirm").modal("hide");
        });
        $("#btnConfirmNo").on("click", function () {
            $("#modConfirm").data("result", false);
            $("#modConfirm").modal("hide");
        });
        $("#lnkLic").on("click", function () { showLic(localStorage.getItem("lic_accept") !== "y"); });
    };

    if (localStorage.getItem("lic_accept") !== "y") {
        showLic(true);
        $("#modLicense .btn-success").on("click", function () {
            $("#modLicense").modal("hide");
            localStorage.setItem("lic_accept", "y");
            init();
        });
        $("#modLicense .btn-danger").on("click", function () {
            $("#modLicense").modal("hide");
            $(".container").html("<h1>License declined</h1><a href=\"/\">Reload</a>");
        });
    }
    else {
        init();
    }
});
