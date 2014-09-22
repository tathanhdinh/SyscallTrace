module Morphism where

import qualified Text.Printf as P
import qualified Data.Graph.Inductive as G

type Object = String

data Morphism = Morphism { 
  source :: Object, 
  target :: Object, 
  name :: String
} 
  
{-type Path = [Morphism]-}

instance Show Morphism where
  show morphism = P.printf "%-15s : %-10s -> %-10s" 
                  (name morphism) (source morphism) (target morphism)

type ActiveObjects = [Object]

{-G.Gr a b (a: label of node, b label of edge-}
type OpenGraph = G.Gr String Object
type TransOpenGraph = G.Gr String ()

data ActiveOpenGraph = ActiveOpenGraph {
  graph :: OpenGraph,
  input :: G.Node,
  output :: G.Node
}
