<?php
include "koneksi.php";
// ambil data dan sanitasi
function bersih($data){
    return htmlspecialchars($data, ENT_QUOTES, 'UTF-8');
}

// Ambil data dari input form
$xnim           = bersih($_POST['nim'] ?? '');
$xnama          = bersih($_POST['nama'] ?? '');
$xtempatLahir   = bersih($_POST['tempatLahir'] ?? '');
$xtanggalLahir  = bersih($_POST['tanggalLahir'] ?? '');
$xtglLahir      = date("Y-m-d", strtotime($xtanggalLahir));
$xjmlSaudara    = bersih($_POST['jmlSaudara'] ?? '');
$xalamat        = bersih($_POST['alamat'] ?? '');
$xkota          = bersih($_POST['kota'] ?? '');
$xjk            = bersih($_POST['jk'] ?? '');            // L / P
$xstatusKeluarga= bersih($_POST['statusKeluarga'] ?? ''); // K / B
$xhobi          = isset($_POST['hobi']) ? bersih(implode(", ", $_POST['hobi'])) : '';
$xemail         = bersih($_POST['email'] ?? '');
$raw_password   = bersih($_POST['password'] ?? '');

// Lakukan validasi pada password asli (panjang, kompleksitas, dll.)
if (empty($raw_password) || strlen($raw_password) < 10) {
    die("Password minimal 10 karakter.");
}

// Hashing password menggunakan password_hash()
$hashed_password = password_hash($raw_password, PASSWORD_BCRYPT);

// Siapkan query INSERT
$sql = "INSERT INTO mhs (nim, nama, tempatLahir, tanggalLahir, jmlSaudara, alamat, kota, jenisKelamin, statusKeluarga, hobi, email, pass)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?)";

$stmt = $koneksi->prepare($sql);
if (!$stmt) {
    die("Prepare failed: (" . $koneksi->errno . ") " . $koneksi->error);
}

// Bind parameters: 12 kolom → 12 tipe "s"
$stmt->bind_param(
    "ssssisssssss",
    $xnim,
    $xnama,
    $xtempatLahir,
    $xtglLahir,
    $xjmlSaudara,
    $xalamat,
    $xkota,
    $xjk,
    $xstatusKeluarga,
    $xhobi,
    $xemail,
    $hashed_password
);

if ($stmt->execute()) {
    echo "Data berhasil disimpan! <br>";
    echo "<a href='tampilDataMhs.php'>Lihat Data</a>";
} else {
    echo "Error: " . $stmt->error;
}

// Tutup statement lalu koneksi
$stmt->close();
$koneksi->close();
?>
