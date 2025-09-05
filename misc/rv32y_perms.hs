{-# OPTIONS_GHC -Wall #-}
{-# LANGUAGE OverloadedLists #-}
{-# LANGUAGE OverloadedStrings #-}

-- | Check that the RV32 encodings, with and without Zylevels1, are sensible and
--   that the procedure we give for computing permissions has the intended
--   effect.
--
--   1. Each defined compressed permission set holds only defined permissions
--
--   2. For each defined compressed permission set, it had better be stable
--      under the transformation rules (that is, a fixed point thereof).
--
--   3. For each subset of all defined permissions, the result of evaluating
--      the rules is a defined compressed permission set.
--
--   4. Removing permissions from a defined compressed permission set and
--      evaluating the rules selects the best result, in that all other defined
--      compressed permission sets that could have been chosen are subsets of
--      the one picked.
module Main where

import           Control.Monad
import qualified Data.Set  as S
import qualified Data.Text as T

data P = PR | PW | PC | PLM | PLG | PSL | PX | PASR | PM
 deriving (Bounded, Enum, Eq, Ord, Show)

type SP = S.Set P

allPermsL1, allPermsL0 :: SP
allPermsL1 = S.fromList [minBound .. maxBound]
allPermsL0 = S.difference allPermsL1 [PLG, PSL] -- remove Zylevel perms

validsL1, validsL0 :: S.Set SP
validsL0 = S.fromList $
  [ -- Quadrant 0
    {- No permissions             -}     [                         ]
  , {- Data RO                    -}     [PR                       ]
  , {- Data WO                    -}     [    PW                   ]
  , {- Data RW                    -}     [PR, PW                   ]

  , -- Quadrant 2
    {- Data & Cap RO              -}     [PR,     PC               ]

  , -- Quadrant 3
    {- Data & Cap RO              -}     [PR,     PC, PLM          ]
  , {- Data & Cap RW              -}     [PR, PW, PC, PLM          ]
  ]
  -- Quadrant 1
  ++ {- Exec, Data & Cap RW & ASR -} wPM [PR, PW, PC, PLM, PX, PASR]
  ++ {- Exec, Data & Cap RO       -} wPM [PR,     PC, PLM, PX      ]
  ++ {- Exec, Data & Cap RW       -} wPM [PR, PW, PC, PLM, PX      ]
  ++ {- Exec, Data RW             -} wPM [PR, PW,          PX      ]
 where
  wPM s = [s, S.insert PM s]

validsL1 = S.fromList $
  [ -- Quadrant 0
    {- No permissions             -}     [                                   ]
  , {- Data RO                    -}     [PR                                 ]
  , {- Data WO                    -}     [    PW                             ]
  , {- Data RW                    -}     [PR, PW                             ]

  , -- Quadrant 2
    {- Data & Cap RO, !SL, !LG    -}     [PR,     PC                         ]
  , {- Data & Cap RW, SL, !LG     -}     [PR, PW, PC, PLM,      PSL          ]
  , {- Data & Cap RW, !SL, !LG    -}     [PR, PW, PC, PLM                    ]

  , -- Quadrant 3
    {- Data & Cap RO, !SL, LG     -}     [PR,     PC, PLM, PLG               ]
  , {- Data & Cap RW, SL, LG      -}     [PR, PW, PC, PLM, PLG, PSL          ]
  , {- Data & Cap RW, !SL, LG     -}     [PR, PW, PC, PLM, PLG               ]
  ]
  -- Quadrant 1
  ++ {- Exec, Data & Cap RW & ASR -} wPM [PR, PW, PC, PLM, PLG, PSL, PX, PASR]
  ++ {- Exec, Data & Cap RO       -} wPM [PR,     PC, PLM, PLG,      PX      ]
  ++ {- Exec, Data & Cap RW       -} wPM [PR, PW, PC, PLM, PLG, PSL, PX      ]
  ++ {- Exec, Data RW             -} wPM [PR, PW,                    PX      ]
 where
  wPM s = [s, S.insert PM s]

(||^), (&&^) :: Applicative f => f Bool -> f Bool -> f Bool
(||^) = liftA2 (||)
(&&^) = liftA2 (&&)

sAny, sAll :: SP -> SP -> Bool
sAny s = not . S.null . S.intersection s
sAll   = S.isSubsetOf

sImplies :: P -> P -> SP -> Bool
sImplies p q = (not <$> S.member p) ||^ S.member q

data Rule = Rule T.Text P (SP -> Bool)

rulesL0, rulesL1 :: [Rule]
rulesL0 =
  [ Rule "C on R"         PC   $ S.member PR
  , Rule "X on R"         PX   $ S.member PR
  , Rule "W on LM | !C"   PW   $ S.member PLM ||^ (not <$> S.member PC)
  , Rule "X on W | C"     PX   $ sAny [PC, PW]
  , Rule "LM on C"        PLM  $ S.member PC
  , Rule "X dependence"   PX   $ sAll [PC, PLM] ||^ (not <$> sAny [PC, PLM])
  , Rule "ASR on W C X"   PASR $ sAll [PW, PC, PX]
  , Rule "M on X"         PM   $ S.member PX
  ]

rulesL1 =
  [ Rule "C on R"         PC   $ S.member PR
  , Rule "X on R"         PX   $ S.member PR
  , Rule "W on LM | !C"   PW   $ S.member PLM ||^ (not <$> S.member PC)
  , Rule "X on W | C"     PX   $ sAny [PC, PW]
  , Rule "LM on C"        PLM  $ S.member PC
  , Rule "LM on W | LG"   PLM  $ sAny [PW, PLG]
  , Rule "LG on LM"       PLG  $ S.member PLM
  , Rule "SL on W LM"     PSL  $ sAll [PW, PLM]
  , Rule "X dependence"   PX   $ (sAll [PC, PLM, PLG] &&^ sImplies PW PSL)
                                 ||^ (not <$> sAny [PC, PLM, PLG, PSL])
  , Rule "ASR on W C X"   PASR $ sAll [PW, PC, PX]
  , Rule "M on X"         PM   $ S.member PX
  ]

data RuleResult = RRFire   -- Rule fired and removed target permission
                | RRAbsent -- Rule fired, but permission not present
                | RRNoFire -- Rule did not fire
 deriving (Eq, Ord, Show)

type LogEntry = (T.Text, RuleResult)

interpRule :: Rule -> SP -> (LogEntry, SP)
interpRule (Rule n p f) s = case () of
  _ | f s                -> ((n, RRNoFire), s)
  _ | not (S.member p s) -> ((n, RRAbsent), s)
  _ | otherwise          -> ((n, RRFire  ), S.delete p s)

interpRules :: [Rule] -> SP -> ([LogEntry], SP)
interpRules = \rs s0 -> let (l, s') = foldl interp (id, s0) rs in (l [], s')
 where
  interp :: ([LogEntry] -> [LogEntry], SP)
         -> Rule
         -> ([LogEntry] -> [LogEntry], SP)
  interp (l, s) r = let (le,s') = interpRule r s in (l . (le:), s')

stepsUnder :: [Rule] -> SP -> Maybe ([LogEntry], SP)
stepsUnder rs s = let e@(_, s') = interpRules rs s in
                  if s == s' then Nothing else Just e

conditions :: [(T.Text, SP, [Rule], S.Set SP)]
conditions = [("no levels", allPermsL0, rulesL0, validsL0)
             ,("zylevels1", allPermsL1, rulesL1, validsL1)
             ]

main :: IO ()
main = forM_ conditions $ \(cn, cperms, crules, cdefines) -> do
  putStrLn $ "[*] Checking condition " ++ (show cn)

  putStrLn "[*] Checking that all defined encodings are subsets of all perms..."
  forM_ cdefines $ \s ->
    unless (S.isSubsetOf s cperms) $ putStrLn $
      "[-] Defined permission set " ++ (show s)
      ++ " exceeds permissions " ++ (show cperms)

  putStrLn "[*] Checking that all defined encodings are fixed points..."
  forM_ cdefines $ \s ->
   forM_ (stepsUnder crules s) $ \(l, s') ->
    putStrLn $ "[-] Defined set " ++ (show s) ++ " stepped to " ++ (show s')
               ++ " thus: " ++ (show l)

  putStrLn "[*] Checking that all permission sets eval to defined encodings..."
  forM_ (S.powerSet cperms) $ \s ->
    let (l, s') = interpRules crules s in
    unless (S.member s' cdefines) $
    putStrLn $ "[-] Permission set " ++ (show s)
               ++ " steps to invalid " ++ (show s') ++ " thus: " ++ (show l)

  putStrLn "[*] Checking that removal picks the best..."
  forM_ cdefines $ \sStart ->
    forM_ (S.powerSet sStart) $ \sShedding ->
      let
        sShed = S.difference sStart sShedding
        (_, sComputed) = interpRules crules sShed
      in
      forM_ cdefines $ \sDefined ->
        when (S.isSubsetOf sDefined sShed
              && S.isProperSubsetOf sComputed sDefined) $
        putStrLn $ "[-] Removing set " ++ (show sShedding)
                   ++ " from " ++ (show sStart)
                   ++ " resulted in " ++ (show sComputed)
                   ++ " but could have used " ++ (show sDefined)
