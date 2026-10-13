package io.nessus.oid4vc.demo.checkin;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class CheckinStore {

    private final Map<String, BoardingPass> boardingPasses = new ConcurrentHashMap<>();

    public BoardingPass getBoardingPass(String boardingRef) {
        return boardingPasses.get(boardingRef);
    }

    public Map<String, BoardingPass> getAllBoardingPasses() {
        return Map.copyOf(boardingPasses);
    }

    public void putBoardingPass(String boardingRef, BoardingPass boardingPass) {
        boardingPasses.put(boardingRef, boardingPass);
    }

    public void clear() {
        boardingPasses.clear();
    }
}
