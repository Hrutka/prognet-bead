# Programozható Hálózatok
## Per Packet Value Remarking

### Csapat:
Molnár Dominik (rkqzs8@inf.elte.hu), Kovács Réka (rdgw40@inf.elte.hu)

### Probléma:
Csomagok egyenlőbb elosztása, felhasználók priorizálása.

### Megoldás:
- **Throughput mérése:** Az idő méréséhez a packet-ek timestamp-jét használjuk fel, úgy hogy ha az eltelt idő tegyük fel, hogy 1 másodperc, akkor mindig egész másodperctől egész másodpercig mérünk, így nem kell az eltelt időt tárolni. Amikor átlépünk a következő másodpercbe, akkor kezdő értéknek beállítjuk az első adott másodpercben érkezett csomag méretét és a további adott másodpercben érkező csomagok méretét hozzáadjuk majd. Így megkapjuk, hogy mekkora volt a throughput az adott másodpercben.
- **TVF, throughput value function:** Egy előre definiált skála szerint létrehozunk egy megfeleltető függvényt, mely bemenete a packet beérkezésekor mért throughput és ahhez rendel hozzá egy címkét, ami a packet prioritását jelöli.
  * Meghatározunk egy koordinátarendszert, ahol az x tengely 0-tól a maximális sávszélességig terjed, az y pedig 0-tól egy általunk választott egész számig, jelen esetben legyen 10. És felveszünk egy függvényt, mely egyenlő arányben egy egész számot rendel 1-től 10-ig minden throughput értékhez, hasonlóan mint a lenti ábrán.
![Throughput value function](TVF.png#center "Throughput value function")
  * 0 és a bemeneti throughput között random számot generálunk.
  * Az így kapott számot behelyettesítjük az első pontban említett függvénybe.
  * Az így megkapott érték lesz a packet címkéje.
- **Eredmény mérése:**
  * Forgalmat generálunk adott rátával (pl. 10Mbps).
  * A küldött csomagokat felcímkézzük.
  * Fogadó oldalon számoljuk, hogy címkénként hány csomag érkezett, aminek egyenlő eloszlásúnak kell lennie a címkék szerint.
